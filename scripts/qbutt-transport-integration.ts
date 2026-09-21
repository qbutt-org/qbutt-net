import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createSocket } from "node:dgram";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createConnection, createServer, type Socket } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";

const binary = resolve(process.argv[2]);
const interfaceName = process.argv[3] ?? Object.entries(networkInterfaces())
    .find(([, addresses]) => addresses?.some(address => address.internal && address.family === "IPv4"))?.[0];
assert(interfaceName, "Pass the loopback interface name as argument 2");
const root = await mkdtemp(join(tmpdir(), "qbutt-transport-reserves-"));
const sockets = new Set<Socket>();
const evidence: Record<string, unknown> = { status: "running", checks: [], protocol: 6,
    binarySha256: createHash("sha256").update(new Uint8Array(await Bun.file(binary).arrayBuffer())).digest("hex") };
const checks = evidence.checks as string[];
const DNS_PORT = 10653;
const ECHO_PORT = 27001;
const REFUSED_PORT = 27002;

function bounded<T>(promise: Promise<T>, milliseconds = 15000): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    return Promise.race([promise, new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("Fixture operation timed out")), milliseconds);
    })]).finally(() => clearTimeout(timer));
}

class Wire {
    private buffer = Buffer.alloc(0);
    private wake?: () => void;
    private ended = false;
    constructor(readonly socket: Socket) {
        sockets.add(socket);
        socket.on("data", data => {
            this.buffer = Buffer.concat([this.buffer, data]);
            assert(this.buffer.length <= 1024 * 1024);
            this.wake?.();
        });
        socket.on("error", () => { this.ended = true; this.wake?.(); });
        socket.on("close", () => { sockets.delete(socket); this.ended = true; this.wake?.(); });
    }
    async read(size: number, timeout = 15000): Promise<Buffer> {
        while (this.buffer.length < size) {
            if (this.ended) throw new Error("Fixture socket closed");
            await bounded(new Promise<void>(resolve => { this.wake = resolve; }), timeout);
            this.wake = undefined;
        }
        const result = this.buffer.subarray(0, size);
        this.buffer = this.buffer.subarray(size);
        return result;
    }
}

async function upstream(host = "127.0.0.1") {
    const state = { available: true, udpAvailable: true, dns: 0, udpDns: 0, refused: 0, echoes: 0, connections: 0, udpDropped: 0 };
    const udp = createSocket("udp4");
    await new Promise<void>(resolve => udp.bind(0, host, resolve));
    udp.on("message", (packet, source) => {
        if (!state.udpAvailable) {
            state.udpDropped++;
            return;
        }
        if (packet.length > 22 && packet.readUInt16BE(8) === DNS_PORT) {
            const reply = Buffer.from(packet);
            reply.writeUInt16BE(0x8180, 12);
            state.udpDns++;
            udp.send(reply, source.port, source.address);
        } else udp.send(packet, source.port, source.address);
    });
    const server = createServer(socket => {
        const wire = new Wire(socket);
        state.connections++;
        void (async () => {
            if (!state.available) return;
            const greeting = await wire.read(2);
            assert.equal(greeting[0], 5);
            assert((await wire.read(greeting[1])).includes(0));
            socket.write(Buffer.from([5, 0]));
            const request = await wire.read(10);
            assert.equal(request[0], 5);
            assert.equal(request[2], 0);
            assert.equal(request[3], 1);
            if (request[1] === 3) {
                const response = Buffer.from([5, 0, 0, 1, ...host.split(".").map(Number), 0, 0]);
                response.writeUInt16BE(udp.address().port, 8);
                socket.write(response);
                await new Promise<void>(resolve => socket.once("close", resolve));
                return;
            }
            assert.equal(request[1], 1);
            const port = request.readUInt16BE(8);
            if (port === REFUSED_PORT) {
                state.refused++;
                socket.write(Buffer.from([5, 5, 0, 1, 127, 0, 0, 1, 0, 0]));
                return;
            }
            assert(port === DNS_PORT || port === ECHO_PORT);
            socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
            if (port === DNS_PORT) {
                const size = (await wire.read(2)).readUInt16BE();
                const query = Buffer.from(await wire.read(size));
                assert.equal(query.readUInt16BE(4), 1);
                state.dns++;
                query.writeUInt16BE(0x8180, 2);
                const prefix = Buffer.alloc(2);
                prefix.writeUInt16BE(query.length);
                socket.write(Buffer.concat([prefix, query]));
            } else {
                while (!socket.destroyed) {
                    const size = (await wire.read(2, 120000)).readUInt16BE();
                    const bytes = await wire.read(size);
                    state.echoes += size;
                    socket.write(bytes);
                }
            }
        })().catch(error => {
            if (!socket.destroyed && !String(error).includes("socket closed"))
                evidence.upstreamError = String(error);
        }).finally(() => socket.end());
    });
    await new Promise<void>(resolve => server.listen(0, host, resolve));
    return { state, server, udp, port: (server.address() as { port: number }).port, host };
}

const primary = await upstream();
const reserve = await upstream();
const independent = await upstream("127.0.0.2");
const child = spawn(binary, ["--stdio"], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
let stderr = "";
child.stderr.on("data", data => { stderr += data; assert(stderr.length < 65536); });
const exited = new Promise<number | null>(resolve => child.once("exit", resolve));
const pending = new Map<number, (value: any) => void>();
createInterface({ input: child.stdout }).on("line", line => {
    assert(line.length <= 65536);
    const reply = JSON.parse(line);
    const receive = pending.get(reply.id);
    assert(receive, "Unexpected control response");
    pending.delete(reply.id);
    receive(reply);
});
let nextId = 0;
async function rpc(method: string, fields: Record<string, unknown> = {}) {
    const id = ++nextId;
    const result = bounded(new Promise<any>(resolve => pending.set(id, resolve)));
    child.stdin.write(JSON.stringify({ v: 6, id, method, ...fields }) + "\n");
    return result;
}
async function status(pathId: string) {
    const result = await rpc("status");
    assert(!result.error);
    return result.result.paths.find((path: any) => path.pathId === pathId);
}
async function until(predicate: () => Promise<boolean>, seconds = 45) {
    const end = Date.now() + seconds * 1000;
    while (Date.now() < end) {
        if (await predicate()) return;
        await Bun.sleep(200);
    }
    throw new Error("Expected transport state was not reached");
}
async function connect(endpoint: any, port = ECHO_PORT, command = 1) {
    const socket = createConnection({ host: endpoint.host, port: endpoint.port });
    const wire = new Wire(socket);
    socket.write(Buffer.from([5, 1, 2]));
    assert.deepEqual(await wire.read(2), Buffer.from([5, 2]));
    const username = Buffer.from(endpoint.socksUsername);
    const password = Buffer.from(endpoint.socksPassword);
    socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password]));
    assert.deepEqual(await wire.read(2), Buffer.from([1, 0]));
    const address = Buffer.from([5, command, 0, 1, 127, 0, 0, 1, 0, 0]);
    address.writeUInt16BE(port, 8);
    socket.write(address);
    const reply = await wire.read(10);
    return { wire, code: reply[1], reply };
}
async function echo(wire: Wire) {
    const bytes = Buffer.alloc(16384, 0x73);
    const prefix = Buffer.alloc(2);
    prefix.writeUInt16BE(bytes.length);
    wire.socket.write(Buffer.concat([prefix, bytes]));
    assert.deepEqual(await wire.read(bytes.length), bytes);
}

try {
    assert.equal((await rpc("hello")).result.protocol, 6);
    const configPath = join(root, "nodes.json");
    const proxies = [primary, reserve, independent].map((server, index) => ({ name: ["primary", "reserve", "other"][index],
        type: "socks5", server: server.host, port: server.port, udp: true }));
    await writeFile(configPath, JSON.stringify({ proxies }));
    const identity = (server: string) => createHash("sha256").update(`qbutt-configured-server-v1\0${server}`).digest("hex");
    const input = { configPath, proxyName: "primary", reserveNames: ["reserve"], configuredServerId: identity(primary.host),
        pathId: "primary", generation: 1, interfaceName, dns: { server: `127.0.0.1:${DNS_PORT}`, bootstrapServer: `127.0.0.1:${DNS_PORT}`, family: "ipv4" } };
    assert.equal((await rpc("open", { ...input, reserveNames: ["other"] })).error.code, "server_identity_changed");
    assert.equal((await rpc("open", { ...input, reserveNames: ["reserve", "reserve"] })).error.code, "invalid_transport_selection");
    const first = (await rpc("open", input)).result;
    assert(first);
    const other = (await rpc("open", { ...input, pathId: "other", generation: 7, proxyName: "other",
        configuredServerId: identity(independent.host), reserveNames: [] })).result;
    const healthy = await connect(other);
    assert.equal(healthy.code, 0);
    await echo(healthy.wire);
    checks.push("explicit-same-server-reserves-only");

    const idleTcp = await connect(first);
    await echo(idleTcp.wire);
    const idleUdp = await connect(first, 0, 3);
    const idleClient = createSocket("udp4");
    try {
        await new Promise<void>(resolve => idleClient.bind(0, "127.0.0.1", resolve));
        const packet = Buffer.concat([Buffer.from([0, 0, 0, 1, 127, 0, 0, 1, 0, 0]), Buffer.alloc(128, 0x61)]);
        packet.writeUInt16BE(ECHO_PORT, 8);
        const response = bounded(new Promise<Buffer>(resolve => idleClient.once("message", resolve)));
        idleClient.send(packet, idleUdp.reply.readUInt16BE(8), "127.0.0.1");
        assert.deepEqual(await response, packet);
        await status("primary");
        await Bun.sleep(3500);
        assert.equal((await status("primary")).transport.state, "active");
        assert.equal(primary.state.dns + primary.state.udpDns + reserve.state.dns + reserve.state.udpDns, 0);
        checks.push("completed-tcp-and-udp-responses-followed-by-idle-do-not-probe");
    } finally {
        idleClient.close();
        idleUdp.wire.socket.destroy();
        idleTcp.wire.socket.destroy();
    }

    const refused = await connect(first, REFUSED_PORT);
    if (refused.code === 0) {
        // Some adapters defer the upstream handshake until the first write.
        refused.wire.socket.write(Buffer.from([0, 1, 0x73]));
        await assert.rejects(refused.wire.read(1), /socket closed/);
    }
    refused.wire.socket.destroy();
    await until(async () => (await status("primary")).transport.state === "reachable");
    assert.equal(primary.state.dns, 1);
    assert.equal(reserve.state.dns, 0);
    assert.equal((await status("primary")).generation, 1);
    checks.push("peer-refusal-with-current-dns-success-does-not-switch");

    const association = await connect(first, 0, 3);
    assert.equal(association.code, 0);
    const currentTcp = await connect(first);
    assert.equal(currentTcp.code, 0);
    let keepDownloading = true;
    let currentTcpBytes = 0;
    const activeTcp = (async () => {
        while (keepDownloading) {
            await echo(currentTcp.wire);
            currentTcpBytes += 16384;
            await Bun.sleep(100);
        }
    })();
    const udpClient = createSocket("udp4");
    let udpResponses = 0;
    let sending: ReturnType<typeof setInterval> | undefined;
    try {
        await new Promise<void>(resolve => udpClient.bind(0, "127.0.0.1", resolve));
        udpClient.on("message", () => udpResponses++);
        const packet = Buffer.concat([Buffer.from([0, 0, 0, 1, 127, 0, 0, 1, 0, 0]), Buffer.alloc(1024, 0x63)]);
        packet.writeUInt16BE(ECHO_PORT, 8);
        const response = bounded(new Promise<Buffer>(resolve => udpClient.once("message", resolve)));
        udpClient.send(packet, association.reply.readUInt16BE(8), "127.0.0.1");
        assert.deepEqual(await response, packet);
        primary.state.udpAvailable = false;
        sending = setInterval(() => udpClient.send(packet, association.reply.readUInt16BE(8), "127.0.0.1"), 100);
        // The upstream UDP association remains open and accepts writes. Only
        // its responses disappear; a read/connect error cannot trigger this.
        await until(async () => (await status("primary")).transport.state === "ready");
        assert(primary.state.udpDropped > 2);
        assert.equal(udpResponses, 1);
    } finally {
        if (sending) clearInterval(sending);
        udpClient.close();
        keepDownloading = false;
        await activeTcp;
    }
    assert.equal((await status("primary")).transport.recommended, "reserve");
    assert.equal(reserve.state.udpDns, 1);
    assert.equal(reserve.state.dns, 0);
    assert(currentTcpBytes > 16384 * 20);
    const replaced = await rpc("transport.replace", { pathId: "primary", generation: 1, nextGeneration: 2, proxyName: "reserve" });
    assert(!replaced.error, "Reserve replacement failed");
    assert.equal(replaced.result.generation, 2);
    assert.equal(replaced.result.configuredServerId, first.configuredServerId);
    assert.notEqual(replaced.result.socksPassword, first.socksPassword);
    await until(async () => association.wire.socket.destroyed);
    await until(async () => currentTcp.wire.socket.destroyed);
    const retired = createConnection({ host: first.host, port: first.port });
    await bounded(new Promise<void>((resolve, reject) => {
        retired.once("connect", () => { retired.destroy(); reject(new Error("Retired listener remained open")); });
        retired.once("error", () => resolve());
    }));
    const throughReserve = await connect(replaced.result);
    assert.equal(throughReserve.code, 0);
    await echo(throughReserve.wire);
    await echo(healthy.wire);
    assert.equal((await status("other")).generation, 7);
    assert.equal((await rpc("transport.replace", { pathId: "primary", generation: 1, nextGeneration: 3, proxyName: "primary" })).error.code, "generation_mismatch");
    throughReserve.wire.socket.destroy();
    assert(!(await rpc("close", { pathId: "primary", generation: 2 })).error);
    checks.push("same-edge-new-generation-exact-payload-and-unaffected-other-connection");
    checks.push("one-way-udp-blackhole-with-continuing-outbound-and-healthy-concurrent-tcp");

    primary.state.available = false;
    const tcpFailed = (await rpc("open", { ...input, pathId: "tcp-failed", generation: 3 })).result;
    assert.equal((await rpc("resolve", { pathId: "tcp-failed", generation: 3,
        host: "fixture.invalid", family: "ipv4" })).error.code, "path_dns_failed");
    await until(async () => (await status("tcp-failed")).transport.state === "ready");
    const failedTcp = await connect(tcpFailed);
    if (failedTcp.code === 0) {
        failedTcp.wire.socket.write(Buffer.from([0, 1, 0x73]));
        await assert.rejects(failedTcp.wire.read(1), /socket closed/);
    }
    const tcpReplacement = await rpc("transport.replace", { pathId: "tcp-failed", generation: 3, nextGeneration: 4, proxyName: "reserve" });
    assert(!tcpReplacement.error);
    const recoveredTcp = await connect(tcpReplacement.result);
    await echo(recoveredTcp.wire);
    recoveredTcp.wire.socket.destroy();
    assert(!(await rpc("close", { pathId: "tcp-failed", generation: 4 })).error);
    await echo(healthy.wire);
    primary.state.available = true;
    checks.push("tcp-primary-failure-with-successful-same-resolver-reserve-and-exact-payload");

    reserve.state.udpAvailable = false;
    const unavailable = (await rpc("open", { ...input, pathId: "unavailable", generation: 10 })).result;
    const stillHealthyTcp = await connect(unavailable);
    let maintainTcp = true;
    const healthyTcpDuringFailure = (async () => {
        while (maintainTcp) {
            await echo(stillHealthyTcp.wire);
            await Bun.sleep(100);
        }
    })();
    const declined = await connect(unavailable, 0, 3);
    assert.equal(declined.code, 0);
    const noResolver = createSocket("udp4");
    const unanswered = Buffer.concat([Buffer.from([0, 0, 0, 1, 127, 0, 0, 1, 0, 0]), Buffer.alloc(128, 0x19)]);
    unanswered.writeUInt16BE(ECHO_PORT, 8);
    await new Promise<void>((resolve, reject) => noResolver.send(unanswered, declined.reply.readUInt16BE(8), "127.0.0.1",
        error => error ? reject(error) : resolve()));
    noResolver.close();
    await until(async () => (await status("unavailable")).transport.state === "unavailable");
    const attempts = primary.state.connections + reserve.state.connections;
    await Bun.sleep(31000);
    assert.equal((await status("unavailable")).transport.state, "unavailable");
    assert.equal(primary.state.connections + reserve.state.connections, attempts);
    maintainTcp = false;
    await healthyTcpDuringFailure;
    stillHealthyTcp.wire.socket.destroy();
    checks.push("udp-resolver-unreachable-on-all-reserves-without-rotation-or-self-triggered-probe-loop");

    proxies[1].port++;
    await writeFile(configPath, JSON.stringify({ proxies }));
    assert.equal((await rpc("transport.replace", { pathId: "unavailable", generation: 10, nextGeneration: 11, proxyName: "reserve" })).error.code,
        "transport_config_changed");
    assert.equal(await status("unavailable"), undefined);
    await until(async () => declined.wire.socket.destroyed);
    await echo(healthy.wire);
    checks.push("changed-selected-config-rejected-before-replacement");

    proxies[1].port--;
    await writeFile(configPath, JSON.stringify({ proxies }));
    const cancelled = (await rpc("open", { ...input, pathId: "cancelled", generation: 20 })).result;
    const cancelledUdp = await connect(cancelled, 0, 3);
    const cancellationClient = createSocket("udp4");
    await new Promise<void>((resolve, reject) => cancellationClient.send(unanswered, cancelledUdp.reply.readUInt16BE(8), "127.0.0.1",
        error => error ? reject(error) : resolve()));
    cancellationClient.close();
    await until(async () => (await status("cancelled")).transport.state === "checking");
    const closeStarted = Date.now();
    assert(!(await rpc("close", { pathId: "cancelled", generation: 20 })).error);
    assert(Date.now() - closeStarted < 3000, "Close did not cancel the in-flight UDP health probe");
    primary.state.udpAvailable = reserve.state.udpAvailable = true;
    await Bun.sleep(300);
    assert.equal(await status("cancelled"), undefined);
    await echo(healthy.wire);
    checks.push("close-cancels-in-flight-probe-and-late-success-cannot-reopen");
    assert(!evidence.upstreamError, String(evidence.upstreamError));
    assert(!(await rpc("shutdown")).error);
    assert.equal(await bounded(exited), 0);
    assert.equal(stderr, "");
    evidence.status = "passed";
} catch (error) {
    evidence.status = "failed";
    evidence.error = error instanceof Error ? error.stack : String(error);
    process.exitCode = 1;
} finally {
    if (child.exitCode === null) {
        child.kill();
        await bounded(exited);
    }
    for (const socket of sockets) socket.destroy();
    for (const upstream of [primary, reserve, independent]) upstream.udp.close();
    await Promise.all([primary, reserve, independent].map(({ server }) => new Promise<void>(resolve => server.close(() => resolve()))));
    await rm(join(root, "nodes.json"), { force: true });
    await writeFile(join(root, "evidence.json"), JSON.stringify(evidence, null, 2));
    console.log(JSON.stringify({ status: evidence.status, evidence: join(root, "evidence.json"), checks: checks.length }));
}
