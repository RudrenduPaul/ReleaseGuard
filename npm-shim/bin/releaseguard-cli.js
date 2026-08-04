#!/usr/bin/env node
"use strict";

/**
 * npm launcher for the releaseguard-cli PyPI package.
 *
 * ReleaseGuard's implementation is Python (it wraps presidio-analyzer /
 * presidio-anonymizer, which are themselves Python packages -- re-shelling
 * or re-implementing bindings in Node would mean maintaining a second
 * copy of Presidio's detection logic, exactly the kind of independent
 * detection claim this project explicitly avoids). This npm package
 * exists so `npx releaseguard-cli` works for npm-first agent tooling, but
 * it does not bundle a Node reimplementation -- it locates and execs the
 * real `releaseguard` binary installed from PyPI. This is a deliberate
 * cross-registry tradeoff, documented in the README, not an oversight.
 */

const { spawnSync } = require("node:child_process");

function findPythonCli() {
  const probe = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(probe, ["releaseguard"], { encoding: "utf8" });
  if (result.status === 0 && result.stdout.trim()) {
    return result.stdout.trim().split(/\r?\n/)[0];
  }
  return null;
}

function main() {
  const binPath = findPythonCli();

  if (!binPath) {
    process.stderr.write(
      [
        "releaseguard-cli (npm) is a launcher for the Python implementation.",
        "",
        "The 'releaseguard' command was not found on your PATH. Install it with:",
        "",
        "  pip install releaseguard-cli",
        "  python -m spacy download en_core_web_sm   # Presidio's NLP model, one-time",
        "",
        "Then re-run this command.",
        "",
      ].join("\n")
    );
    process.exit(1);
  }

  const args = process.argv.slice(2);
  const result = spawnSync(binPath, args, { stdio: "inherit" });

  if (result.error) {
    process.stderr.write(`Failed to run releaseguard: ${result.error.message}\n`);
    process.exit(1);
  }

  process.exit(result.status === null ? 1 : result.status);
}

main();
