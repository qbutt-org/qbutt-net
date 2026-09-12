import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createSocket } from "node:dgram";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createConnection, createServer, type Socket } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { createServer as createTLSServer, type TLSSocket } from "node:tls";

const binary = resolve(process.argv[2] ?? "../qbutt-build/qbutt-net-dns.exe");
const interfaceName = Object.entries(networkInterfaces()).find(([, ips]) => ips?.some(ip => ip.internal && ip.family === "IPv4"))?.[0];
assert(interfaceName, "Loopback fixture interface is required");
const temporary = await mkdtemp(join(tmpdir(), "qbutt-path-dns-"));
const sockets = new Set<Socket>();
const errors: string[] = [];
const queries: { path: string; host: string; type: number }[] = [];
const destinations: { path: string; host: string; port: number; udp: boolean }[] = [];
const sni: string[] = [];
let tcpVerifiedBytes = 0, udpVerifiedBytes = 0;
const deadline = <T>(promise: Promise<T>, name: string, timeout = 8000) => {
  let timer: ReturnType<typeof setTimeout>;
  return Promise.race([promise, new Promise<T>((_, reject) => { timer = setTimeout(() => reject(new Error(`Timed out: ${name}`)), timeout); })])
    .finally(() => clearTimeout(timer));
};
class Wire {
  buffer = Buffer.alloc(0); ended = false; waiting?: () => void;
  constructor(readonly socket: Socket) {
    sockets.add(socket); socket.on("close", () => { sockets.delete(socket); this.ended = true; this.waiting?.(); });
    socket.on("error", () => { this.ended = true; this.waiting?.(); });
    socket.on("data", data => { this.buffer = Buffer.concat([this.buffer, data]); assert(this.buffer.length < 131072); this.waiting?.(); });
  }
  async read(count: number): Promise<Buffer> {
    while (this.buffer.length < count) {
      if (this.ended) throw new Error("closed");
      await deadline(new Promise<void>(resolve => { this.waiting = resolve; }), "wire"); this.waiting = undefined;
    }
    const data = this.buffer.subarray(0, count); this.buffer = this.buffer.subarray(count); return data;
  }
  async address() {
    const type = (await this.read(1))[0];
    let host: string;
    if (type === 1) host = [...await this.read(4)].join(".");
    else if (type === 4) host = [...await this.read(16)].map(byte => byte.toString(16)).join(":");
    else { assert.equal(type, 3); host = (await this.read((await this.read(1))[0])).toString(); }
    return { host, port: (await this.read(2)).readUInt16BE(0), type };
  }
}
const ipv4 = (host: string, port: number) => Buffer.from([1, ...host.split(".").map(Number), port >> 8, port & 255]);
const domain = (host: string, port: number) => Buffer.concat([Buffer.from([3, Buffer.byteLength(host)]), Buffer.from(host), Buffer.from([port >> 8, port & 255])]);
const framed = (data: Buffer) => { const length = Buffer.alloc(2); length.writeUInt16BE(data.length); return Buffer.concat([length, data]); };
const dnsName = (host: string) => Buffer.concat([...host.split(".").map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])), Buffer.from([0])]);
const dnsAddress = "127.0.0.8:53";
async function dnsReply(wire: Wire, path: string, lastByte: number) {
  const data = await wire.read((await wire.read(2)).readUInt16BE(0));
  let cursor = 12; const labels: string[] = [];
  while (data[cursor]) { const size = data[cursor++]; labels.push(data.subarray(cursor, cursor + size).toString()); cursor += size; }
  cursor++; const type = data.readUInt16BE(cursor); cursor += 4;
  const host = labels.join("."); queries.push({ path, host, type });
  if (host === "slow.test") return;
  const valid = path === "bootstrap" ? ["edge-a.test", "edge-a-target.test", "edge-b.test"].includes(host) :
    ["same.test", "localhost", "udp.test", "family.test", "cache.test", "fresh.test", "bounds.test", "wrong-id.test", "truncated.test", "no-cache.test", "cname.test", "cycle.test", "expires.test"].includes(host);
  const header = Buffer.from(data.subarray(0, 12)); header.writeUInt16BE(valid ? 0x8180 : 0x8183, 2);
  const count = valid ? (host === "bounds.test" ? 65 : 1) : 0;
  header.writeUInt16BE(count, 6); header.writeUInt16BE(0, 8); header.writeUInt16BE(0, 10);
  if (host === "wrong-id.test") header[0] ^= 1;
  if (host === "truncated.test") header.writeUInt16BE(0x8380, 2);
  let answer = Buffer.alloc(0);
  if (valid) {
    const cname = host === "cname.test" ? "same.test" : host === "cycle.test" ? "cycle.test" :
      path === "bootstrap" && host === "edge-a.test" ? "edge-a-target.test" : undefined;
    const address = cname ? dnsName(cname) : type === 1 ? Buffer.from([127, 0, 0, lastByte]) : Buffer.concat([Buffer.alloc(15), Buffer.from([lastByte])]);
    const fields = Buffer.alloc(12); fields.writeUInt16BE(0xc00c, 0); fields.writeUInt16BE(cname ? 5 : type, 2);
    fields.writeUInt16BE(1, 4); fields.writeUInt32BE(host === "no-cache.test" ? 0 : host === "expires.test" ? 1 : 30, 6); fields.writeUInt16BE(address.length, 10);
    answer = Buffer.concat(Array.from({ length: count }, () => Buffer.concat([fields, address])));
  }
  wire.socket.write(framed(Buffer.concat([header, data.subarray(12, cursor), answer])));
}
const bootstrap = createServer(socket => { const wire = new Wire(socket); void dnsReply(wire, "bootstrap", 1).catch(error => errors.push(String(error))); });
await new Promise<void>(resolve => bootstrap.listen(0, "127.0.0.1", resolve));
const bootstrapAddress = `127.0.0.1:${(bootstrap.address() as any).port}`;
let rogueConnections = 0;
const rogue = createServer(socket => { rogueConnections++; socket.destroy(); });
await new Promise<void>(resolve => rogue.listen(0, "127.0.0.1", resolve));
let blackholeConnections = 0;
const blackhole = createServer(socket => { blackholeConnections++; new Wire(socket); });
await new Promise<void>(resolve => blackhole.listen(0, "127.0.0.1", resolve));
const certificate = await readFile(new URL("../test/config/example.org.pem", import.meta.url));
const key = await readFile(new URL("../test/config/example.org-key.pem", import.meta.url));
const upstreams: { server: ReturnType<typeof createTLSServer>; udp: ReturnType<typeof createSocket>; name: string; port: number }[] = [];
for (const [name, lastByte] of [["a", 2], ["b", 3]] as const) {
  const udp = createSocket("udp4");
  udp.on("message", (data, source) => {
    assert([1, 4].includes(data[3]), "UDP destination must be pre-resolved numerically");
    const offset = data[3] === 1 ? 8 : 20;
    const host = data[3] === 1 ? [...data.subarray(4, 8)].join(".") : `::${data[19]}`;
    assert.equal(host, data[3] === 1 ? `127.0.0.${lastByte}` : `::${lastByte}`, "UDP path DNS crossed paths");
    destinations.push({ path: name, host, port: data.readUInt16BE(offset), udp: true });
    udp.send(data, source.port, source.address);
  });
  await new Promise<void>(resolve => udp.bind(0, "127.0.0.1", resolve));
  const server = createTLSServer({ cert: certificate, key }, (socket: TLSSocket) => {
    sni.push(socket.servername || ""); const wire = new Wire(socket);
    void (async () => {
      assert.equal((await wire.read(2))[0], 5); await wire.read(1); socket.write(Buffer.from([5, 0]));
      const header = await wire.read(3); const target = await wire.address();
      if (header[1] === 3) {
        socket.write(Buffer.concat([Buffer.from([5, 0, 0]), ipv4("0.0.0.0", udp.address().port)])); return;
      }
      assert.equal(header[1], 1); assert.notEqual(target.type, 3, "Adapter must receive numeric torrent destinations");
      socket.write(Buffer.concat([Buffer.from([5, 0, 0]), ipv4("127.0.0.1", 1)]));
      if (`${target.host}:${target.port}` === dnsAddress) { await dnsReply(wire, name, lastByte); return; }
      assert.equal(target.host, target.type === 1 ? `127.0.0.${lastByte}` : `${"0:".repeat(15)}${lastByte}`, "TCP path DNS crossed paths");
      destinations.push({ path: name, ...target, udp: false });
      const bytes = await wire.read(4096); socket.write(bytes);
    })().catch(error => { if (String(error) !== "Error: closed") errors.push(String(error)); socket.destroy(); });
  });
  server.on("tlsClientError", error => errors.push(String(error)));
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  upstreams.push({ server, udp, name, port: (server.address() as any).port });
}
const child = spawn(binary, ["--stdio"], { stdio: ["pipe", "pipe", "pipe"] });
let stderr = ""; child.stderr.on("data", data => { stderr += data; });
const pending = new Map<number, (reply: any) => void>(); let requestID = 0;
createInterface({ input: child.stdout }).on("line", line => { const reply = JSON.parse(line); assert.equal(reply.v, 2); pending.get(reply.id)?.(reply); pending.delete(reply.id); });
const exited = new Promise<number | null>(resolve => child.once("exit", resolve));
function request(method: string, fields: object = {}) {
  const id = ++requestID; const promise = deadline(new Promise<any>(resolve => pending.set(id, resolve)), method);
  child.stdin.write(JSON.stringify({ v: 2, id, method, ...fields }) + "\n"); return promise;
}
async function authenticate(endpoint: any) {
  const socket = createConnection(endpoint.port, endpoint.host); const wire = new Wire(socket);
  await deadline(new Promise<void>((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); }), "connect");
  socket.write(Buffer.from([5, 1, 2])); assert.deepEqual(await wire.read(2), Buffer.from([5, 2]));
  socket.write(Buffer.concat([Buffer.from([1, endpoint.socksUsername.length]), Buffer.from(endpoint.socksUsername),
    Buffer.from([endpoint.socksPassword.length]), Buffer.from(endpoint.socksPassword)]));
  assert.deepEqual(await wire.read(2), Buffer.from([1, 0])); return wire;
}
async function tcp(endpoint: any, host: string, expect = 0) {
  const wire = await authenticate(endpoint); wire.socket.write(Buffer.concat([Buffer.from([5, 1, 0]), domain(host, 43210)]));
  const response = await wire.read(3); assert.equal(response[1], expect); await wire.address();
  if (expect === 0) { const bytes = Buffer.alloc(4096, endpoint.pathId === "a" ? 0x1a : 0x2b); wire.socket.write(bytes); assert.deepEqual(await wire.read(bytes.length), bytes); tcpVerifiedBytes += bytes.length; }
  wire.socket.destroy();
}
const configPath = join(temporary, "subscription.json");
try {
  await writeFile(configPath, JSON.stringify({ dns: { enable: true, nameserver: [`127.0.0.1:${(rogue.address() as any).port}`] }, hosts: { "same.test": "127.0.0.99" },
    proxies: [...upstreams.map(item => ({ name: item.name, type: "socks5", server: `edge-${item.name}.test`, port: item.port, udp: true, tls: true, "skip-cert-verify": true })),
      { name: "g", type: "gost-relay", server: "127.0.0.1", port: (blackhole.address() as any).port, udp: true }] }));
  assert.equal((await request("hello")).result.protocol, 2);
  const params = (id: string, generation = 1, family = "dual") => ({ configPath, proxyName: id.startsWith("a") ? "a" : id, pathId: id, generation, interfaceName,
    dns: { server: dnsAddress, bootstrapServer: bootstrapAddress, family } });
  assert.equal((await request("open", { ...params("a"), dns: undefined })).error.code, "dns_policy_required");
  assert.equal((await request("open", { ...params("a"), dns: { server: "dns.example:53", bootstrapServer: bootstrapAddress, family: "dual" } })).error.code, "invalid_dns_policy");
  const a = (await request("open", params("a"))).result; const b = (await request("open", params("b"))).result;
  assert(a && b); assert.equal(a.capabilities.dns, "path-tcp");
  for (const [endpoint, byte] of [[a, 2], [b, 3]] as const) {
    const result = await request("resolve", { pathId: endpoint.pathId, generation: 1, host: "same.test", family: "dual" });
    assert.deepEqual(result.result.addresses, [`127.0.0.${byte}`, `::${byte}`]);
    assert.deepEqual((await request("resolve", { pathId: endpoint.pathId, generation: 1, host: "family.test", family: "ipv6" })).result.addresses, [`::${byte}`]);
    await tcp(endpoint, "same.test"); await tcp(endpoint, "localhost");
    const association = await authenticate(endpoint); association.socket.write(Buffer.concat([Buffer.from([5, 3, 0]), ipv4("0.0.0.0", 0)]));
    assert.deepEqual(await association.read(3), Buffer.from([5, 0, 0])); const relay = await association.address();
    const client = createSocket("udp4");
    try {
      for (let packetIndex = 0; packetIndex < 2; packetIndex++) {
        const bytes = Buffer.alloc(1024, byte); const packet = Buffer.concat([Buffer.alloc(3), domain("udp.test", 43210), bytes]);
        const received = deadline(new Promise<Buffer>(resolve => client.once("message", resolve)), "UDP DNS relay");
        client.send(packet, relay.port, relay.host); assert.deepEqual((await received).subarray(10), bytes); udpVerifiedBytes += bytes.length;
      }
    } finally { client.close(); association.socket.destroy(); }
    assert.equal(queries.filter(query => query.path === endpoint.pathId && query.host === "udp.test").length, 2, "Repeated UDP packets must use bounded TTL cache");
  }
  const a4 = (await request("open", params("a4", 1, "ipv4"))).result; assert(a4);
  const a6 = (await request("open", params("a6", 1, "ipv6"))).result; assert(a6);
  await tcp(a6, "family.test");
  const association6 = await authenticate(a6); association6.socket.write(Buffer.concat([Buffer.from([5, 3, 0]), ipv4("0.0.0.0", 0)]));
  assert.deepEqual(await association6.read(3), Buffer.from([5, 0, 0])); const relay6 = await association6.address();
  const udp6 = createSocket("udp4");
  try {
    const bytes = Buffer.alloc(1024, 0x66);
    const response = deadline(new Promise<Buffer>(resolve => udp6.once("message", resolve)), "IPv6 destination UDP");
    udp6.send(Buffer.concat([Buffer.alloc(3), domain("family.test", 43210), bytes]), relay6.port, relay6.host);
    const packet = await response; assert.equal(packet[3], 4); assert.deepEqual(packet.subarray(22), bytes); udpVerifiedBytes += bytes.length;
  } finally { udp6.close(); association6.socket.destroy(); }
  assert.equal((await request("resolve", { pathId: "a4", generation: 1, host: "family.test", family: "ipv6" })).error.code, "path_dns_failed");
  assert.equal((await request("resolve", { pathId: "a", generation: 9, host: "same.test", family: "dual" })).error.code, "generation_mismatch");
  assert.equal((await request("resolve", { pathId: "a", generation: 1, host: "missing.test", family: "dual" })).error.code, "path_dns_failed");
  await tcp(a, "missing.test", 4);
  for (const host of ["bounds.test", "wrong-id.test", "truncated.test", "cycle.test"])
    assert.equal((await request("resolve", { pathId: "a", generation: 1, host, family: "ipv4" })).error.code, "path_dns_failed");
  for (let index = 0; index < 2; index++)
    assert((await request("resolve", { pathId: "a", generation: 1, host: "no-cache.test", family: "ipv4" })).result);
  assert.equal(queries.filter(query => query.path === "a" && query.host === "no-cache.test").length, 2, "TTL zero must not be cached");
  assert.deepEqual((await request("resolve", { pathId: "a", generation: 1, host: "cname.test", family: "dual" })).result.addresses, ["127.0.0.2", "::2"]);
  const expiring = { pathId: "a", generation: 1, host: "expires.test", family: "ipv4" };
  assert((await request("resolve", expiring)).result); assert((await request("resolve", expiring)).result);
  assert.equal(queries.filter(query => query.host === "expires.test").length, 1);
  await Bun.sleep(1100); assert((await request("resolve", expiring)).result);
  assert.equal(queries.filter(query => query.host === "expires.test").length, 2, "Expired DNS answers were reused");
  assert(queries.filter(query => query.path === "bootstrap").every(query => /^edge-(a(-target)?|b)\.test$/.test(query.host)), "Torrent names escaped to bootstrap");
  assert(sni.length > 0 && sni.every(host => ["edge-a.test", "edge-b.test"].includes(host)), "TLS server hostname was replaced during bootstrap");
  assert.equal(rogueConnections, 0, "Imported DNS policy was executed");
  assert((await request("open", params("g"))).result);
  const handshakeStart = Date.now();
  assert.equal((await request("resolve", { pathId: "g", generation: 1, host: "same.test", family: "ipv4" })).error.code, "path_dns_failed");
  assert(Date.now() - handshakeStart < 6000, "Adapter handshake escaped DNS timeout");
  assert.deepEqual((await request("close", { pathId: "g", generation: 1 })).result, {});
  for (const command of [1, 3]) {
    const g = (await request("open", params("g", command === 1 ? 2 : 3))).result;
    assert(g); const acceptedBefore = blackholeConnections;
    const connection = await authenticate(g); connection.socket.write(Buffer.concat([Buffer.from([5, command, 0]), ipv4(command === 1 ? "127.0.0.2" : "0.0.0.0", command === 1 ? 43210 : 0)]));
    let datagram: ReturnType<typeof createSocket> | undefined;
    try {
      if (command === 3) {
        assert.deepEqual(await connection.read(3), Buffer.from([5, 0, 0])); const relay = await connection.address();
        datagram = createSocket("udp4"); datagram.send(Buffer.concat([Buffer.alloc(3), ipv4("127.0.0.2", 43210), Buffer.from([1])]), relay.port, relay.host);
      }
      await deadline((async () => { while (blackholeConnections === acceptedBefore) await Bun.sleep(10); })(), "GOST pending handshake");
      const closed = new Promise<void>(resolve => connection.socket.once("close", resolve)); const start = Date.now();
      assert.deepEqual((await request("close", { pathId: "g", generation: g.generation })).result, {});
      await deadline(closed, "GOST handshake close"); assert(Date.now() - start < 2000, "Pending adapter handshake blocked path close");
    } finally { datagram?.close(); connection.socket.destroy(); }
  }
  const waiting = await authenticate(a); waiting.socket.write(Buffer.concat([Buffer.from([5, 1, 0]), domain("slow.test", 43210)]));
  await Bun.sleep(200);
  const closed = new Promise<void>(resolve => waiting.socket.once("close", resolve));
  const closeStart = Date.now(); assert.deepEqual((await request("close", { pathId: "a", generation: 1 })).result, {});
  await deadline(closed, "close pending DNS"); assert(Date.now() - closeStart < 2000, "Path close did not cancel pending DNS");
  assert.equal((await request("resolve", { pathId: "a", generation: 1, host: "same.test", family: "dual" })).error.code, "path_not_found");
  const a2 = (await request("open", params("a", 2))).result; assert(a2);
  assert.equal((await request("resolve", { pathId: "a", generation: 1, host: "same.test", family: "dual" })).error.code, "generation_mismatch");
  const beforeFresh = queries.filter(query => query.path === "a" && query.host === "same.test").length;
  assert((await request("resolve", { pathId: "a", generation: 2, host: "same.test", family: "dual" })).result);
  assert.equal(queries.filter(query => query.path === "a" && query.host === "same.test").length, beforeFresh + 2, "New generation reused stale DNS cache");
  const start = Date.now(); const slow = request("resolve", { pathId: "b", generation: 1, host: "slow.test", family: "dual" });
  child.stdin.end(); assert.equal((await slow).error.code, "path_dns_failed");
  assert.equal(await deadline(exited, "EOF during DNS"), 0); assert(Date.now() - start < 6000, "Serial resolve blocked EOF beyond DNS bound");
  assert.equal(stderr, ""); assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed: true, queries: queries.length, tcpVerifiedBytes, udpVerifiedBytes,
    checks: ["explicit v2 DNS policy", "two-path independent A/AAAA", "TLS server hostname preserved", "numeric IPv4/IPv6 TCP and UDP destinations", "SOCKS unspecified UDP bind bootstrap", "UDP TTL cache, TTL zero and expiry", "bootstrap/destination CNAME and cycle rejection", "localhost resolved through path", "family and generation guards", "NXDOMAIN no fallback", "malformed/truncated/over-limit DNS rejected", "imported rogue DNS unused", "GOST handshake timeout and TCP/UDP close", "pending DNS cancelled by close", "generation cache isolation", "EOF bounded during resolver timeout"] }));
} finally {
  if (child.exitCode === null) child.kill();
  for (const socket of sockets) socket.destroy();
  bootstrap.close(); rogue.close(); blackhole.close();
  for (const upstream of upstreams) { upstream.server.close(); upstream.udp.close(); }
  await rm(temporary, { recursive: true, force: true });
}
