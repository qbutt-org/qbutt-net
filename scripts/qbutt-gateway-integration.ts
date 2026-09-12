import assert from "node:assert/strict";
import { mkdtemp, readFile, rmdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

// Build and register these exact executable paths with the qbutt Windows
// firewall helper before launching this integration (including the driver).
const [gatewayArgument, driverArgument] = process.argv.slice(2);
assert(gatewayArgument && driverArgument, "Pass gateway and native QUIC integration driver executables");
const root = await mkdtemp(join(tmpdir(), "qbutt-gateway-"));
await rmdir(root); // Remove only the fresh empty directory; the fixture recreates it.
const child = Bun.spawn([resolve(driverArgument), resolve(gatewayArgument), root], {
    stdout: "pipe", stderr: "pipe", windowsHide: true, timeout: 60000,
});
const [code, stdout, stderr] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
const evidence = JSON.parse(await readFile(join(root, "evidence.json"), "utf8"));
assert.equal(code, 0, `Gateway fixture failed: ${stdout} ${stderr}`);
assert.equal(evidence.status, "passed");
console.log(JSON.stringify({ evidence: join(root, "evidence.json"), ...evidence }));
