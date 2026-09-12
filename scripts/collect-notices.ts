import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";

interface Module {
  Path: string;
  Version?: string;
  Sum?: string;
  Dir?: string;
  Replace?: Module;
}
interface BuildInfo {
  GoVersion: string;
  Path: string;
  Main: Module;
  Deps: Module[];
  Settings: { Key: string; Value: string }[];
}
interface Notice { file: string; sha256: string; text: string }

const [binaryArg, outputArg, go = "go"] = process.argv.slice(2);
assert(binaryArg && outputArg, "Usage: bun scripts/collect-notices.ts <qbutt-net.exe> <output-directory> [go-executable]");
const repository = resolve(import.meta.dir, "..");
const binary = resolve(binaryArg);
const output = resolve(outputArg);
const outputRelative = relative(repository, output);
assert(outputRelative === ".." || outputRelative.startsWith(`..${sep}`) || isAbsolute(outputRelative), "Keep generated notices outside the source repository");

async function command(args: string[], env: Record<string, string | undefined> = {}) {
  const child = Bun.spawn(args, { cwd: repository, env: { ...process.env, GOTOOLCHAIN: "local", ...env }, stdout: "pipe", stderr: "pipe" });
  const timer = setTimeout(() => child.kill(), 60000);
  try {
    const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    assert.equal(code, 0, `Command failed: ${basename(args[0])} ${args[1]}\n${stderr.slice(0, 4096)}`);
    return stdout.trim();
  } finally { clearTimeout(timer); }
}

const build: BuildInfo = JSON.parse(await command([go, "version", "-m", "-json", binary]));
assert.equal(build.Path, "github.com/metacubex/mihomo/cmd/qbutt-net", "Expected a qbutt-net executable");
const settings = new Map(build.Settings.map(({ Key, Value }) => [Key, Value]));
const revision = settings.get("vcs.revision");
assert(revision && /^[a-f0-9]{40}$/.test(revision), "Binary must contain its source commit");
assert.equal(settings.get("vcs.modified"), "false", "Release notices require a clean source build");
assert.equal(await command(["git", "rev-parse", "HEAD"]), revision, "Binary and notice source revisions must match");

const target = Object.fromEntries(["GOOS", "GOARCH", "CGO_ENABLED", "GOAMD64"].map(key => [key, settings.get(key)]).filter(([, value]) => value !== undefined));
const listArgs = [go, "list", "-deps", "-json=Module"];
if (settings.get("-tags")) listArgs.push("-tags", settings.get("-tags")!);
listArgs.push("./cmd/qbutt-net");
const modules = new Map<string, Module>();
// go list emits indented JSON objects whose top-level opening braces start a
// line. Join those objects into an array without altering nested JSON values.
const listedPackages: { Module?: Module }[] = JSON.parse(`[${(await command(listArgs, target)).replace(/\r?\n(?=\{)/g, ",")}]`);
for (const { Module: module } of listedPackages) {
  if (module) modules.set(module.Path, module);
}

async function notices(root: string): Promise<Notice[]> {
  const pending = [root];
  const found: Notice[] = [];
  let entries = 0;
  while (pending.length) {
    const directory = pending.pop()!;
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      assert(++entries <= 100000, "Module notice search exceeded its file limit");
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== ".git") pending.push(path);
      } else if (entry.isFile() && /^(?:licen[sc]e|copying|notice|patents|copyright)(?:[._-].*)?$/i.test(entry.name)) {
        assert((await stat(path)).size <= 1024 * 1024, "Notice file exceeds 1 MiB");
        const bytes = await readFile(path);
        assert(!bytes.includes(0), "Notice file is not plain text");
        found.push({ file: relative(root, path).replaceAll("\\", "/"), sha256: createHash("sha256").update(bytes).digest("hex"), text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) });
      }
    }
  }
  return found.sort((left, right) => left.file.localeCompare(right.file, "en"));
}

const inventory: { module: string; version: string; sourceModule: string; sourceVersion: string; sourceArchive: string; moduleSum: string; notices: Notice[] }[] = [];
for (const dependency of [...build.Deps].sort((left, right) => left.Path.localeCompare(right.Path, "en"))) {
  const listed = modules.get(dependency.Path);
  assert(listed, `Built module is absent from source dependencies: ${dependency.Path}`);
  assert.equal(listed.Version, dependency.Version, `Dependency version changed: ${dependency.Path}`);
  const source = dependency.Replace ?? dependency;
  const local = listed.Replace ?? listed;
  assert.equal(local.Path, source.Path, `Replacement source changed: ${dependency.Path}`);
  assert.equal(local.Version, source.Version, `Replacement version changed: ${dependency.Path}`);
  assert(local.Dir && source.Version && source.Sum, `Versioned module source required: ${source.Path}`);
  const files = await notices(local.Dir);
  assert(files.length, `No LICENSE/COPYING/NOTICE found: ${source.Path}@${source.Version}`);
  const escapedPath = source.Path.replace(/[A-Z]/g, character => `!${character.toLowerCase()}`);
  const escapedVersion = source.Version.replace(/[A-Z]/g, character => `!${character.toLowerCase()}`);
  inventory.push({ module: dependency.Path, version: dependency.Version!, sourceModule: source.Path, sourceVersion: source.Version, sourceArchive: `https://proxy.golang.org/${escapedPath}/@v/${escapedVersion}.zip`, moduleSum: source.Sum, notices: files });
}

const componentNotices = (await readdir(repository))
  .filter(name => /^(?:licen[sc]e|copying|notice)(?:[._-].*)?$/i.test(name))
  .sort();
const componentFiles: Notice[] = [];
for (const file of componentNotices) {
  const bytes = await readFile(join(repository, file));
  componentFiles.push({ file, sha256: createHash("sha256").update(bytes).digest("hex"), text: bytes.toString("utf8") });
}
assert(componentFiles.length, "Component license is missing");

const component = { module: build.Main.Path, revision, source: `https://github.com/qbutt-org/qbutt-net/tree/${revision}`, notices: componentFiles };
const manifest = {
  schema: 1,
  binary: { name: basename(binary), sha256: createHash("sha256").update(await readFile(binary)).digest("hex"), goVersion: build.GoVersion, target },
  component: { ...component, notices: componentFiles.map(({ text, ...file }) => file) },
  modules: inventory.map(module => ({ ...module, notices: module.notices.map(({ text, ...file }) => file) })),
};
const sections = [
  "qbutt-net source and dependency notices",
  `Component source: ${component.source}`,
  `Compiler: ${build.GoVersion}`,
  "The following texts are copied from the exact component/module sources used by this binary. File names are retained; no aggregate license classification is inferred.",
];
for (const notice of componentFiles) sections.push(`\n=== qbutt-net / ${notice.file} ===\n${notice.text}`);
for (const module of inventory) {
  sections.push(`\n=== ${module.module}@${module.version} ===\nSource: ${module.sourceModule}@${module.sourceVersion}\nArchive: ${module.sourceArchive}\nChecksum: ${module.moduleSum}`);
  for (const notice of module.notices) sections.push(`\n--- ${notice.file} ---\n${notice.text}`);
}
await mkdir(output, { recursive: true });
await Promise.all([
  writeFile(join(output, "qbutt-net-notices.json"), JSON.stringify(manifest, null, 2) + "\n"),
  writeFile(join(output, "qbutt-net-notices.txt"), sections.join("\n\n") + "\n"),
]);
console.log(JSON.stringify({ modules: inventory.length, noticeFiles: inventory.reduce((count, module) => count + module.notices.length, componentFiles.length), inventory: join(output, "qbutt-net-notices.json"), texts: join(output, "qbutt-net-notices.txt") }));
