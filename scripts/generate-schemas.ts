import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { contractFiles, renderSchema } from "../src/contracts.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

for (const contract of contractFiles()) {
  const target = join(repositoryRoot, contract.path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, renderSchema(contract.schema), { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`wrote ${contract.path}\n`);
}
