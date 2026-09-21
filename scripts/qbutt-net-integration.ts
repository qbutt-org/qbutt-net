import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createSocket } from "node:dgram";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createConnection, createServer, type Socket } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";

const binary = resolve(process.argv[2] ?? "../qbutt-build/qbutt-net.exe");
const interfaceName = process.argv[3] ?? Object.entries(networkInterfaces())
  .find(([, addresses]) => addresses?.some(address => address.internal && address.family === "IPv4"))?.[0];
assert(interfaceName, "Pass the local loopback interface name as argument 2");
const temporary = await mkdtemp(join(tmpdir(), "qbutt-net-fixture-"));
const deadline = <T>(promise: Promise<T>, label: string): Promise<T> => {
  let timer: ReturnType<typeof setTimeout>;
  return Promise.race([promise, new Promise<T>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Timed out: ${label}`)), 8000);
  })]).finally(() => clearTimeout(timer));
};

// An integration wire reader, shared by the controlled upstream and clients.
class Wire {
  private buffer = Buffer.alloc(0);
  private waiting?: () => void;
  private ended = false;
  constructor(readonly socket: Socket) {
    socket.on("data", (data: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, data]);
      assert(this.buffer.length < 2 * 1024 * 1024, "fixture receive limit");
      this.waiting?.();
    });
    socket.on("close", () => { this.ended = true; this.waiting?.(); });
    socket.on("error", () => { this.ended = true; this.waiting?.(); });
  }
  async read(size: number): Promise<Buffer> {
    while (this.buffer.length < size) {
      if (this.ended) throw new Error("Unexpected fixture socket close");
      await deadline(new Promise<void>(resolve => { this.waiting = resolve; }), "wire read");
      this.waiting = undefined;
    }
    const bytes = this.buffer.subarray(0, size);
    this.buffer = this.buffer.subarray(size);
    return bytes;
  }
  async address(): Promise<Buffer> {
    const type = await this.read(1);
    if (type[0] === 1) return Buffer.concat([type, await this.read(6)]);
    if (type[0] === 4) return Buffer.concat([type, await this.read(18)]);
    assert.equal(type[0], 3);
    const length = await this.read(1);
    return Buffer.concat([type, length, await this.read(length[0] + 2)]);
  }
}

const sockets = new Set<Socket>();
const upstreamErrors: Error[] = [];
let tcpPayloadBytes = 0;
let udpPayloadBytes = 0;
const udp = createSocket("udp4");
udp.on("message", (packet, source) => {
  udpPayloadBytes += packet.length - 10;
  udp.send(packet, source.port, source.address);
});
await new Promise<void>(resolve => udp.bind(0, "127.0.0.1", resolve));
const udpPort = udp.address().port;
const ipv4 = (port: number) => Buffer.from([1, 127, 0, 0, 1, port >> 8, port & 255]);
const upstream = createServer({ allowHalfOpen: true }, socket => {
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
  const wire = new Wire(socket);
  const inputEnded = new Promise<void>(resolve => socket.once("end", resolve));
  void (async () => {
    assert.equal((await wire.read(2))[0], 5);
    // Mihomo offers the single no-auth method for this generated fixture.
    await wire.read(1);
    socket.write(Buffer.from([5, 0]));
    const header = await wire.read(3);
    const target = await wire.address();
    if (header[1] === 3) {
      socket.write(Buffer.concat([Buffer.from([5, 0, 0]), ipv4(udpPort)]));
      return;
    }
    assert.equal(header[1], 1);
    socket.write(Buffer.concat([Buffer.from([5, 0, 0]), ipv4(1)]));
    // The endpoint echoes actual application bytes after the full proxy dial.
    const payload = await wire.read(32768);
    tcpPayloadBytes += payload.length;
    if (target.readUInt16BE(target.length - 2) === 43211) {
      await inputEnded;
      socket.end(payload);
      return;
    }
    socket.write(payload);
  })().catch(error => { upstreamErrors.push(error); socket.destroy(); });
});
await new Promise<void>(resolve => upstream.listen(0, "127.0.0.1", resolve));
const upstreamPort = (upstream.address() as {port: number}).port;

function launch() {
  const child = spawn(binary, ["--stdio"], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", data => { stderr += data; assert(stderr.length < 4096); });
  const replies = new Map<number, (reply: any) => void>();
  const lines = createInterface({ input: child.stdout });
  lines.on("line", line => {
    assert(Buffer.byteLength(line) < 65536);
    const reply = JSON.parse(line);
    assert.equal(reply.v, 7);
    const receive = replies.get(reply.id);
    assert(receive, "response id must match a request");
    replies.delete(reply.id);
    receive(reply);
  });
  const exited = new Promise<number | null>((resolve, reject) => {
    child.once("exit", resolve);
    child.once("error", reject);
  });
  let id = 0;
  return {
    child, exited, stderr: () => stderr,
    request(method: string, params: Record<string, unknown> = {}) {
      const requestId = ++id;
      const reply = deadline(new Promise<any>(resolve => replies.set(requestId, resolve)), method);
      child.stdin.write(JSON.stringify({ v: 7, id: requestId, method, ...params }) + "\n");
      return reply;
    },
  };
}
const children: ReturnType<typeof launch>[] = [];
function childProcess() { const child = launch(); children.push(child); return child; }
async function connect(endpoint: any) {
  const socket = createConnection(endpoint.port, endpoint.host);
  sockets.add(socket);
  socket.on("close", () => sockets.delete(socket));
  const wire = new Wire(socket);
  await deadline(new Promise<void>((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); }), "connect");
  return wire;
}
async function authenticate(wire: Wire, username: string, password: string) {
  wire.socket.write(Buffer.from([5, 1, 2]));
  assert.deepEqual(await wire.read(2), Buffer.from([5, 2]));
  wire.socket.write(Buffer.concat([Buffer.from([1, username.length]), Buffer.from(username), Buffer.from([password.length]), Buffer.from(password)]));
  return wire.read(2);
}
async function openTCP(endpoint: any, port = 43210) {
  const wire = await connect(endpoint);
  assert.deepEqual(await authenticate(wire, endpoint.socksUsername, endpoint.socksPassword), Buffer.from([1, 0]));
  wire.socket.write(Buffer.concat([Buffer.from([5, 1, 0]), ipv4(port)]));
  assert.deepEqual(await wire.read(3), Buffer.from([5, 0, 0]));
  await wire.address();
  return wire;
}
async function closed(socket: Socket) {
  if (socket.destroyed) return;
  await deadline(new Promise<void>(resolve => socket.once("close", resolve)), "socket close");
}

try {
  const configPath = join(temporary, "profile.yaml");
  await writeFile(configPath, `tun: {enable: true}\ndns: {enable: true, listen: '0.0.0.0:53'}\nexternal-controller: 0.0.0.0:9090\nproxy-providers: {untrusted: {type: http, url: 'http://127.0.0.1:1/never'}}\nrules: ['MATCH,DIRECT']\nproxies:\n  - {name: selected, type: socks5, server: 127.0.0.1, port: ${upstreamPort}, udp: true}\n  - {name: chained, type: socks5, server: 127.0.0.1, port: ${upstreamPort}, DIALER_PROXY: selected}\n  - {name: bypass, type: direct}\n`);
  const child = childProcess();
  assert.equal((await child.request("list", { configPath })).error.code, "hello_required");
  assert.equal((await child.request("hello", { v: 1 })).error.code, "protocol_mismatch");
  assert.equal((await child.request("hello", { v: 4 })).error.code, "protocol_mismatch");
  assert.equal((await child.request("hello", { v: 5 })).error.code, "protocol_mismatch");
  assert.equal((await child.request("hello", { v: 6 })).error.code, "protocol_mismatch");
  const hello = (await child.request("hello")).result;
  assert.equal(hello.protocol, 7);
  assert.equal(hello.upstreamRevision, "d3ec342d441b086ec4318332f59dd05d8a2b5697");
  assert.deepEqual((await child.request("status")).result, { paths: [] });
  const listed = (await child.request("list", { configPath })).result.proxies;
  assert.equal(listed.length, 3);
  assert.deepEqual(Object.keys(listed[0]).sort(), ["configuredServerId", "name", "type"]);
  assert.equal(listed[2].configuredServerId, "");
  const selected = (await child.request("list", { configPath, proxyName: "selected" })).result.proxies;
  assert.deepEqual(selected, [listed[0]]);
  const configuredServerId = selected[0].configuredServerId;
  assert.match(configuredServerId, /^[a-f0-9]{64}$/);
  assert.equal((await child.request("list", { configPath, proxyName: "absent" })).error.code, "proxy_not_found");
  assert.equal((await child.request("list", { configPath, proxyName: "bypass" })).error.code, "invalid_configured_server");
  const boundedConfig = join(temporary, "bounds.yaml");
  await writeFile(boundedConfig, JSON.stringify({ proxies: Array.from({length: 326}, (_, index) => ({name: `node-${index}`, type: "socks5", server: "127.0.0.1"})) }));
  assert.equal((await child.request("list", { configPath: boundedConfig })).result.proxies.length, 326);
  await writeFile(boundedConfig, JSON.stringify({ proxies: Array.from({length: 1025}, (_, index) => ({name: `node-${index}`, type: "socks5"})) }));
  assert.equal((await child.request("list", { configPath: boundedConfig })).error.code, "proxy_limit");
  const longNames = Array.from({length: 1024}, (_, index) => `${index}-${"n".repeat(120)}`);
  await writeFile(boundedConfig, JSON.stringify({ proxies: longNames.map(name => ({name, type: "socks5", server: "127.0.0.1", port: upstreamPort})) }));
  assert.equal((await child.request("list", { configPath: boundedConfig })).error.code, "response_limit");
  const selectedNames = longNames.slice(-4);
  const boundedSelection = (await child.request("list", { configPath: boundedConfig, proxyNames: selectedNames })).result.proxies;
  assert.deepEqual(boundedSelection.map((node: { name: string }) => node.name), selectedNames);
  assert.equal((await child.request("list", { configPath: boundedConfig, proxyNames: [...selectedNames, selectedNames[0]] })).error.code, "invalid_transport_selection");
  assert.equal((await child.request("list", { configPath: boundedConfig, proxyNames: [selectedNames[0], selectedNames[0]] })).error.code, "invalid_transport_selection");
  assert.equal((await child.request("list", { configPath: boundedConfig, proxyNames: ["absent"] })).error.code, "proxy_not_found");
  await writeFile(boundedConfig, "x".repeat(2 * 1024 * 1024 + 1));
  assert.equal((await child.request("list", { configPath: boundedConfig })).error.code, "config_limit");
  const parameters = { configPath, configuredServerId, proxyName: "selected", pathId: "fixture", generation: 1, interfaceName,
    dns: {server: "127.0.0.1:53", bootstrapServer: "127.0.0.1:53", family: "dual"} };
  await writeFile(boundedConfig, JSON.stringify({ proxies: [{ name: "selected", type: "vless", "xhttp-opts": { "download-settings": { PRIVATE_KEY: "existing-client-key.pem" } } }] }));
  assert.equal((await child.request("open", { ...parameters, configPath: boundedConfig })).error.code, "external_credentials_not_supported");
  for (const options of [{ ECH_OPTS: { ENABLE: "true" } }, { "realm-opts": { enable: true } }, { "tlsmirror-opts": { server: "auxiliary.test" } }]) {
    await writeFile(boundedConfig, JSON.stringify({ proxies: [{ name: "selected", type: "vless", ...options }] }));
    assert.equal((await child.request("open", { ...parameters, configPath: boundedConfig })).error.code, "auxiliary_dns_not_supported");
  }
  await writeFile(boundedConfig, JSON.stringify({ proxies: [{ name: "selected", type: "hysteria", OBFS_PROTOCOL: "faketcp" }] }));
  assert.equal((await child.request("open", { ...parameters, configPath: boundedConfig })).error.code, "unbound_transport_not_supported");
  assert.equal((await child.request("open", { ...parameters, interfaceName: "missing-qbutt-interface" })).error.code, "interface_unavailable");
  assert.equal((await child.request("open", { ...parameters, proxyName: "chained" })).error.code, "proxy_chain_not_supported");
  assert.equal((await child.request("open", { ...parameters, proxyName: "bypass" })).error.code, "unsupported_proxy_type");
  const aliasConfig = join(temporary, "identities.json");
  const identityCases = [
    ["ExAmPlE.test.", "example.test"], ["example.test", "example.test"],
    ["b\u00fccher.test", "xn--bcher-kva.test"], ["xn--bcher-kva.test.", "xn--bcher-kva.test"],
    ["2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"], ["2001:db8::1", "2001:db8::1"],
    ["127.0.0.1", "127.0.0.1"], ["::ffff:127.0.0.1", "127.0.0.1"], ["different.test", "different.test"],
  ];
  await writeFile(aliasConfig, JSON.stringify({ proxies: identityCases.map(([server], i) => ({ name: `alias-${i}`,
    type: i % 2 ? "http" : "socks5", server, port: 12000 + i, username: `user-${i}`, password: `generated-${i}` })) }));
  const aliases = (await child.request("list", { configPath: aliasConfig })).result.proxies;
  assert.equal(aliases.length, identityCases.length);
  identityCases.forEach(([, canonical], i) => assert.equal(aliases[i].configuredServerId,
    createHash("sha256").update(`qbutt-configured-server-v1\0${canonical}`).digest("hex")));
  const beforeChange = (await child.request("list", { configPath: aliasConfig, proxyName: "alias-6" })).result.proxies[0];
  assert.equal(beforeChange.configuredServerId, configuredServerId);
  assert.equal((await child.request("open", { ...parameters, configuredServerId: undefined })).error.code, "configured_server_id_required");
  // The same selected name is changed after list; no adapter/listener may be created.
  await writeFile(aliasConfig, JSON.stringify({ proxies: [{ name: "alias-6", type: "socks5", server: "127.0.0.2", port: upstreamPort }] }));
  assert.equal((await child.request("open", { ...parameters, proxyName: "alias-6", configPath: aliasConfig, edgeId: "override" })).error.code, "server_identity_changed");
  assert.deepEqual((await child.request("status")).result, { paths: [] });
  assert.equal(tcpPayloadBytes, 0);
  const endpoint = (await child.request("open", parameters)).result;
  assert(endpoint, "open selected adapter");
  assert.equal(endpoint.host, "127.0.0.1");
  assert.equal(endpoint.configuredServerId, configuredServerId);
  assert.equal(endpoint.capabilities.udp, "source-supported");
  assert.equal(endpoint.capabilities.publicUdp, "unknown");
  const zeroWire = { relayDownloadBytes: 0, relayUploadBytes: 0, carrierDownloadBytes: 0, carrierUploadBytes: 0,
    carrierDownloadPackets: 0, carrierUploadPackets: 0, relayDownloadCopies: 0 };
  assert.deepEqual((await child.request("status")).result, { paths: [{ pathId: "fixture", generation: 1,
    transport: { state: "disabled", recommended: "" }, wire: zeroWire }] });
  assert.equal((await child.request("open", parameters)).error.code, "path_exists");
  const noAuth = await connect(endpoint);
  noAuth.socket.write(Buffer.from([5, 1, 0]));
  assert.deepEqual(await noAuth.read(2), Buffer.from([5, 255]));
  await closed(noAuth.socket);
  const wrongAuth = await connect(endpoint);
  assert.deepEqual(await authenticate(wrongAuth, endpoint.socksUsername, "wrong"), Buffer.from([1, 1]));
  await closed(wrongAuth.socket);
  const tcp = await openTCP(endpoint);
  const payload = Buffer.alloc(32768);
  for (let index = 0; index < payload.length; index++) payload[index] = index * 31 % 256;
  tcp.socket.write(payload);
  assert.deepEqual(await tcp.read(payload.length), payload);
  const halfClosed = await openTCP(endpoint, 43211);
  halfClosed.socket.end(payload);
  assert.deepEqual(await halfClosed.read(payload.length), payload);
  await closed(halfClosed.socket);

  const association = await connect(endpoint);
  assert.deepEqual(await authenticate(association, endpoint.socksUsername, endpoint.socksPassword), Buffer.from([1, 0]));
  association.socket.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
  assert.deepEqual(await association.read(3), Buffer.from([5, 0, 0]));
  const address = await association.address();
  const relayPort = address.readUInt16BE(address.length - 2);
  const udpClient = createSocket("udp4");
  try {
    const packet = Buffer.concat([Buffer.alloc(3), ipv4(43210), payload.subarray(0, 1024)]);
    const received = deadline(new Promise<Buffer>(resolve => udpClient.once("message", resolve)), "UDP echo");
    udpClient.send(packet, relayPort, "127.0.0.1");
    assert.deepEqual(await received, packet);
  } finally { udpClient.close(); }
  assert.deepEqual((await child.request("status")).result, { paths: [{ pathId: "fixture", generation: 1,
    transport: { state: "disabled", recommended: "" }, wire: {
    ...zeroWire, relayDownloadBytes: payload.length * 2 + 1024, relayUploadBytes: payload.length * 2 + 1024,
    relayDownloadCopies: 1,
  } }] });
  assert.equal((await child.request("close", { pathId: "fixture", generation: 2 })).error.code, "generation_mismatch");
  assert.deepEqual((await child.request("close", { pathId: "fixture", generation: 1 })).result, {});
  assert.deepEqual((await child.request("status")).result, { paths: [] });
  await closed(tcp.socket);
  await closed(association.socket);
  const endpoint2 = (await child.request("open", { ...parameters, generation: 2 })).result;
  assert.notEqual(endpoint2.socksPassword, endpoint.socksPassword);
  const pending = await openTCP(endpoint2);
  pending.socket.write(payload);
  assert.deepEqual(await pending.read(payload.length), payload);
  assert.deepEqual((await child.request("status")).result, { paths: [{ pathId: "fixture", generation: 2,
    transport: { state: "disabled", recommended: "" }, wire: {
    ...zeroWire, relayDownloadBytes: payload.length, relayUploadBytes: payload.length,
  } }] });
  child.child.stdin.end();
  assert.equal(await deadline(child.exited, "EOF shutdown"), 0);
  await closed(pending.socket);
  assert.equal(child.stderr(), "");

  const shutdown = childProcess();
  await shutdown.request("hello");
  assert.deepEqual((await shutdown.request("shutdown")).result, {});
  assert.equal(await deadline(shutdown.exited, "shutdown"), 0);
  for (const malformed of ["not-json\n", "x".repeat(65536) + "\n"]) {
    const fault = childProcess();
    fault.child.stdin.end(malformed);
    assert.equal(await deadline(fault.exited, "invalid frame shutdown"), 1);
    assert.equal(fault.stderr().trim(), "qbutt-net control channel terminated");
  }
  assert.equal(tcpPayloadBytes, payload.length * 3);
  assert.equal(udpPayloadBytes, 1024);
  assert.deepEqual(upstreamErrors, []);
  console.log(JSON.stringify({ passed: true, tcpPayloadBytes, udpPayloadBytes, checks: ["version handshake", "selected YAML import", "configured server identity normalization", "selected list validation", "changed server rejected before open", "326-node subscription", "config/proxy/response bounds", "external credential rejection", "auxiliary DNS and unbound transport rejection", "chain alias rejection", "interface validation", "required authentication", "TCP payload", "TCP half-close", "UDP payload", "path-generation wire counters", "generation guard", "accepted socket close", "EOF cleanup", "shutdown", "bounded invalid frames"] }));
} finally {
  for (const child of children) if (child.child.exitCode === null) child.child.kill();
  for (const socket of sockets) socket.destroy();
  upstream.close();
  udp.close();
  await rm(temporary, { recursive: true, force: true });
}
