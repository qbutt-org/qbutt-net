import assert from "node:assert/strict";
import { spawn } from "node:child_process";
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
    socket.on("data", data => {
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
  const child = spawn(binary, ["--stdio"], { stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", data => { stderr += data; assert(stderr.length < 4096); });
  const replies = new Map<number, (reply: any) => void>();
  const lines = createInterface({ input: child.stdout });
  lines.on("line", line => {
    assert(Buffer.byteLength(line) < 65536);
    const reply = JSON.parse(line);
    assert.equal(reply.v, 1);
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
      child.stdin.write(JSON.stringify({ v: 1, id: requestId, method, ...params }) + "\n");
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
  assert.equal((await child.request("hello", { v: 2 })).error.code, "protocol_mismatch");
  assert.equal((await child.request("hello")).result.upstreamRevision, "d3ec342d441b086ec4318332f59dd05d8a2b5697");
  assert.equal((await child.request("list", { configPath })).result.proxies.length, 3);
  const boundedConfig = join(temporary, "bounds.yaml");
  await writeFile(boundedConfig, JSON.stringify({ proxies: Array.from({length: 326}, (_, index) => ({name: `node-${index}`, type: "socks5"})) }));
  assert.equal((await child.request("list", { configPath: boundedConfig })).result.proxies.length, 326);
  await writeFile(boundedConfig, JSON.stringify({ proxies: Array.from({length: 1025}, (_, index) => ({name: `node-${index}`, type: "socks5"})) }));
  assert.equal((await child.request("list", { configPath: boundedConfig })).error.code, "proxy_limit");
  await writeFile(boundedConfig, JSON.stringify({ proxies: Array.from({length: 1024}, (_, index) => ({name: `${index}-${"n".repeat(120)}`, type: "socks5"})) }));
  assert.equal((await child.request("list", { configPath: boundedConfig })).error.code, "response_limit");
  await writeFile(boundedConfig, "x".repeat(2 * 1024 * 1024 + 1));
  assert.equal((await child.request("list", { configPath: boundedConfig })).error.code, "config_limit");
  const parameters = { configPath, proxyName: "selected", pathId: "fixture", generation: 1, interfaceName };
  await writeFile(boundedConfig, JSON.stringify({ proxies: [{ name: "selected", type: "vless", "xhttp-opts": { "download-settings": { PRIVATE_KEY: "existing-client-key.pem" } } }] }));
  assert.equal((await child.request("open", { ...parameters, configPath: boundedConfig })).error.code, "external_credentials_not_supported");
  assert.equal((await child.request("open", { ...parameters, interfaceName: "missing-qbutt-interface" })).error.code, "interface_unavailable");
  assert.equal((await child.request("open", { ...parameters, proxyName: "chained" })).error.code, "proxy_chain_not_supported");
  assert.equal((await child.request("open", { ...parameters, proxyName: "bypass" })).error.code, "unsupported_proxy_type");
  const endpoint = (await child.request("open", parameters)).result;
  assert(endpoint, "open selected adapter");
  assert.equal(endpoint.host, "127.0.0.1");
  assert.equal(endpoint.capabilities.udp, "source-supported");
  assert.equal(endpoint.capabilities.publicUdp, "unknown");
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
  assert.equal((await child.request("close", { pathId: "fixture", generation: 2 })).error.code, "generation_mismatch");
  assert.deepEqual((await child.request("close", { pathId: "fixture", generation: 1 })).result, {});
  await closed(tcp.socket);
  await closed(association.socket);
  const endpoint2 = (await child.request("open", { ...parameters, generation: 2 })).result;
  assert.notEqual(endpoint2.socksPassword, endpoint.socksPassword);
  const pending = await openTCP(endpoint2);
  pending.socket.write(payload);
  assert.deepEqual(await pending.read(payload.length), payload);
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
  console.log(JSON.stringify({ passed: true, tcpPayloadBytes, udpPayloadBytes, checks: ["version handshake", "selected YAML import", "326-node subscription", "config/proxy/response bounds", "external credential rejection", "chain alias rejection", "interface validation", "required authentication", "TCP payload", "TCP half-close", "UDP payload", "generation guard", "accepted socket close", "EOF cleanup", "shutdown", "bounded invalid frames"] }));
} finally {
  for (const child of children) if (child.child.exitCode === null) child.child.kill();
  for (const socket of sockets) socket.destroy();
  upstream.close();
  udp.close();
  await rm(temporary, { recursive: true, force: true });
}
