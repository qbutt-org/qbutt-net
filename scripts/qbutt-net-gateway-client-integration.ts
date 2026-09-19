import assert from "node:assert/strict";
import { mkdtemp, readFile, rmdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const [clientArgument, gatewayArgument, driverArgument] = process.argv.slice(2);
assert(clientArgument && gatewayArgument && driverArgument,
    "Pass qbutt-net, qbutt-gateway and native gateway-client integration driver executables");
const root = await mkdtemp(join(tmpdir(), "qbutt-gateway-client-"));
await rmdir(root);
const child = Bun.spawn([resolve(driverArgument), resolve(clientArgument), resolve(gatewayArgument), root], {
    stdout: "pipe", stderr: "pipe", windowsHide: true, timeout: 60000,
});
const [code, stdout, stderr] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
const evidence = JSON.parse(await readFile(join(root, "evidence.json"), "utf8"));
assert.equal(code, 0, `Gateway client fixture failed: ${stdout} ${stderr}`);
assert.equal(evidence.status, "passed");
assert.equal(evidence.publicInboundProven, false);
assert.equal(evidence.loopbackPublicEndpointProven, true);
assert.equal(evidence.parentEOFCleanup, true);
assert.equal(evidence.udpAssociationsFailClosed, true);
assert.equal(evidence.udpMultiplexBounded, true);
assert.equal(evidence.wireCounters, true);
assert.equal(evidence.gatewayClosedExactlyOnce, true);
assert(evidence.gatewayClosedLatencyMillis >= 0 && evidence.gatewayClosedLatencyMillis < 3000);
assert.equal(evidence.legacyProtocolRejected, true);
assert.equal(evidence.explicitCloseSuppressedEvent, true);
assert.equal(evidence.terminalAfterIncomingTcp, true);
console.log(JSON.stringify({ evidence: join(root, "evidence.json"), ...evidence }));
