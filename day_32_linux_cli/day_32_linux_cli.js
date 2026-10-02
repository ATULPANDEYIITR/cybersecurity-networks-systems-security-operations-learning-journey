#!/usr/bin/env node

/**
 * Linux CLI: ls, cd, cat, grep, find, awk, sed, pipes, and redirection.
 *
 * This Node.js program provides a practical event-driven command workflow.
 * It builds a temporary repository-style filesystem, invokes real Linux
 * utilities when available, and also models pipeline stages directly in
 * JavaScript so the data flow remains visible.
 *
 * The implementation deliberately uses Node-specific facilities such as
 * fs/promises, child_process, streams, async functions, and event emitters.
 */

"use strict";

const fs = require("node:fs/promises");
const fsSync = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { EventEmitter } = require("node:events");

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

function heading(title) {
  console.log(`\n${"=".repeat(72)}\n${title}\n${"=".repeat(72)}`);
}

async function writeFile(filePath, content) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content, "utf8");
}

async function commandExists(command) {
  const candidates = process.platform === "win32"
    ? [command, `${command}.exe`, `${command}.cmd`]
    : [command];

  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return true;
    } catch {
      // The executable is not directly represented by a filesystem path.
    }
  }

  // "which" is a Unix-specific lookup. It is intentionally used only when
  // running on a platform where the requested Linux CLI is meaningful.
  if (process.platform === "win32") {
    return false;
  }

  return new Promise((resolve) => {
    const child = spawn("sh", ["-c", `command -v ${command}`]);
    child.on("close", (code) => resolve(code === 0));
    child.on("error", () => resolve(false));
  });
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      shell: false,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    child.on("error", reject);

    child.on("close", (code, signal) => {
      resolve({
        code,
        signal,
        stdout,
        stderr,
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Repository fixture
// ---------------------------------------------------------------------------

async function createWorkspace() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "linux-cli-js-"));
  const repository = path.join(root, "orion-service");
  const logs = path.join(repository, "logs");
  const config = path.join(repository, "config");
  const source = path.join(repository, "src");
  const reports = path.join(repository, "reports");

  await Promise.all(
    [logs, config, source, reports].map((directory) =>
      fs.mkdir(directory, { recursive: true })
    )
  );

  await writeFile(
    path.join(repository, "README.md"),
    "# Orion Service\nOperational CLI investigation fixture.\n"
  );

  await writeFile(
    path.join(config, "service.conf"),
    [
      "environment=production",
      "port=8080",
      "log_level=INFO",
      "cache_enabled=true",
      "audit_enabled=true",
      "",
    ].join("\n")
  );

  await writeFile(
    path.join(config, "database.conf"),
    [
      "host=db.internal",
      "port=5432",
      "database=orion",
      "pool_size=16",
      "ssl=true",
      "",
    ].join("\n")
  );

  await writeFile(
    path.join(source, "router.js"),
    [
      "export function route(request) {",
      "  return request.path;",
      "}",
      "",
    ].join("\n")
  );

  await writeFile(
    path.join(source, "auth.js"),
    [
      "export function authenticate(token) {",
      "  return Boolean(token);",
      "}",
      "",
    ].join("\n")
  );

  await writeFile(
    path.join(logs, "application.log"),
    [
      "2026-10-02T06:10:01Z INFO request id=2001 route=/health latency_ms=14",
      "2026-10-02T06:10:05Z INFO request id=2002 route=/orders latency_ms=87",
      "2026-10-02T06:10:09Z WARN request id=2003 route=/orders latency_ms=311",
      "2026-10-02T06:10:13Z ERROR request id=2004 route=/orders latency_ms=1102",
      "2026-10-02T06:10:17Z ERROR request id=2005 route=/payments latency_ms=734",
      "2026-10-02T06:10:21Z INFO request id=2006 route=/health latency_ms=12",
      "",
    ].join("\n")
  );

  await writeFile(
    path.join(logs, "access.log"),
    [
      "10.0.0.5 GET /health 200",
      "10.0.0.6 GET /orders 200",
      "10.0.0.7 POST /payments 500",
      "",
    ].join("\n")
  );

  return {
    root,
    repository,
    logs,
    config,
    source,
    reports,
  };
}

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------

async function demoLs(workspace) {
  heading("ls: directory inspection");

  const entries = await fs.readdir(workspace.repository, {
    withFileTypes: true,
  });

  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    console.log(`${entry.isDirectory() ? "d" : "-"} ${entry.name}`);
  }

  console.log("\nRecursive file inventory:");
  const files = [];

  async function visit(directory) {
    const children = await fs.readdir(directory, { withFileTypes: true });

    for (const child of children) {
      const childPath = path.join(directory, child.name);

      if (child.isDirectory()) {
        await visit(childPath);
      } else {
        files.push(path.relative(workspace.repository, childPath));
      }
    }
  }

  await visit(workspace.repository);

  for (const file of files.sort()) {
    console.log(file);
  }
}

// ---------------------------------------------------------------------------
// cd
// ---------------------------------------------------------------------------

async function demoCd(workspace) {
  heading("cd: process working directory");

  const original = process.cwd();

  try {
    console.log(`Starting directory: ${original}`);

    process.chdir(workspace.repository);
    console.log(`After cd orion-service: ${process.cwd()}`);

    process.chdir("logs");
    console.log(`After cd logs: ${process.cwd()}`);

    process.chdir("..");
    console.log(`After cd ..: ${process.cwd()}`);
  } finally {
    process.chdir(original);
  }

  console.log(
    "\nNode's process.chdir changes the current process directory. " +
    "A spawned child inherits the directory unless spawn options override cwd."
  );
}

// ---------------------------------------------------------------------------
// cat
// ---------------------------------------------------------------------------

async function demoCat(workspace) {
  heading("cat: file content and concatenation");

  const files = [
    path.join(workspace.config, "service.conf"),
    path.join(workspace.config, "database.conf"),
  ];

  for (const file of files) {
    const content = await fs.readFile(file, "utf8");
    console.log(`--- ${path.basename(file)} ---`);
    process.stdout.write(content);
  }

  console.log(
    "\nMultiple files can be concatenated conceptually by writing their " +
    "contents to the same stdout stream."
  );
}

// ---------------------------------------------------------------------------
// grep
// ---------------------------------------------------------------------------

async function grepFile(filePath, expression) {
  const content = await fs.readFile(filePath, "utf8");
  const lines = content.split(/\r?\n/);
  const matches = [];

  lines.forEach((line, index) => {
    if (expression.test(line)) {
      matches.push(`${filePath}:${index + 1}:${line}`);
    }
    // Global regular expressions keep state in JavaScript. Reset lastIndex
    // so repeated test() calls examine every line independently.
    expression.lastIndex = 0;
  });

  return matches;
}

async function demoGrep(workspace) {
  heading("grep: content matching");

  const applicationLog = path.join(workspace.logs, "application.log");

  const errors = await grepFile(applicationLog, /\bERROR\b/);
  console.log("ERROR records:");
  errors.forEach(console.log);

  const slow = await grepFile(applicationLog, /latency_ms=(?:[5-9]\d\d|\d{4,})/);
  console.log("\nHigh-latency records:");
  slow.forEach(console.log);

  console.log(
    "\ngrep-style matching is textual. A structured application should use " +
    "a parser when the data format has semantics that regular expressions " +
    "cannot safely preserve."
  );
}

// ---------------------------------------------------------------------------
// find
// ---------------------------------------------------------------------------

async function findFiles(directory, predicate) {
  const matches = [];

  async function visit(current) {
    const entries = await fs.readdir(current, { withFileTypes: true });

    for (const entry of entries) {
      const currentPath = path.join(current, entry.name);

      if (entry.isDirectory()) {
        await visit(currentPath);
      } else if (predicate(currentPath, entry)) {
        matches.push(currentPath);
      }
    }
  }

  await visit(directory);
  return matches;
}

async function demoFind(workspace) {
  heading("find: filesystem predicates");

  const logFiles = await findFiles(
    workspace.repository,
    (filePath) => path.extname(filePath) === ".log"
  );

  console.log("Log files:");
  logFiles.forEach((file) =>
    console.log(path.relative(workspace.repository, file))
  );

  const JavaScriptFiles = await findFiles(
    workspace.repository,
    (filePath) => filePath.endsWith(".js")
  );

  console.log("\nJavaScript source files:");
  JavaScriptFiles.forEach((file) =>
    console.log(path.relative(workspace.repository, file))
  );

  console.log(
    "\nfind's defining concern is path selection. It can filter by name, " +
    "type, size, timestamps, permissions, and directory position."
  );
}

// ---------------------------------------------------------------------------
// awk-style field processing
// ---------------------------------------------------------------------------

function awkStyleLatencySummary(lines) {
  const totals = new Map();

  for (const line of lines) {
    const fields = line.trim().split(/\s+/);

    if (fields.length < 5) {
      continue;
    }

    const level = fields[1];
    const routeField = fields.find((field) => field.startsWith("route="));
    const latencyField = fields.find((field) =>
      field.startsWith("latency_ms=")
    );

    if (!routeField || !latencyField) {
      continue;
    }

    const route = routeField.split("=")[1];
    const latency = Number(latencyField.split("=")[1]);

    if (!Number.isFinite(latency)) {
      continue;
    }

    if (!totals.has(route)) {
      totals.set(route, {
        count: 0,
        totalLatency: 0,
        errors: 0,
      });
    }

    const summary = totals.get(route);
    summary.count += 1;
    summary.totalLatency += latency;

    if (level === "ERROR") {
      summary.errors += 1;
    }
  }

  return totals;
}

async function demoAwk(workspace) {
  heading("awk: records, fields, and aggregation");

  const file = path.join(workspace.logs, "application.log");
  const lines = (await fs.readFile(file, "utf8")).split(/\r?\n/);
  const summaries = awkStyleLatencySummary(lines);

  console.log("route count average_latency_ms errors");

  for (const [route, summary] of summaries) {
    const average = summary.totalLatency / summary.count;
    console.log(
      `${route} ${summary.count} ${average.toFixed(2)} ${summary.errors}`
    );
  }

  console.log(
    "\nThe JavaScript implementation deliberately searches for named fields " +
    "such as route= and latency_ms= instead of relying on fixed field indexes. " +
    "That makes it more tolerant of extra fields in the log format."
  );
}

// ---------------------------------------------------------------------------
// sed
// ---------------------------------------------------------------------------

function sedStyleReplace(text, pattern, replacement) {
  return text.replace(pattern, replacement);
}

async function demoSed(workspace) {
  heading("sed: stream-oriented substitution");

  const file = path.join(workspace.config, "service.conf");
  const original = await fs.readFile(file, "utf8");

  const changed = sedStyleReplace(
    original,
    /^log_level=.*/m,
    "log_level=DEBUG"
  );

  console.log("Original:");
  process.stdout.write(original);

  console.log("\nAfter substitution:");
  process.stdout.write(changed);

  console.log(
    "\nThe replacement is kept in memory. A safe editing workflow can " +
    "write a new file first, inspect it, and replace the original only " +
    "after validation."
  );
}

// ---------------------------------------------------------------------------
// Event-driven pipeline model
// ---------------------------------------------------------------------------

class CliPipeline extends EventEmitter {
  constructor(lines) {
    super();
    this.lines = [...lines];
  }

  pipe(stageName, transform) {
    this.lines = transform(this.lines);
    this.emit("stage", {
      stage: stageName,
      records: this.lines.length,
    });
    return this;
  }

  output() {
    return [...this.lines];
  }
}

async function demoPipes(workspace) {
  heading("pipes: event-driven composition");

  const logFile = path.join(workspace.logs, "application.log");
  const lines = (await fs.readFile(logFile, "utf8"))
    .split(/\r?\n/)
    .filter(Boolean);

  const pipeline = new CliPipeline(lines);

  pipeline.on("stage", ({ stage, records }) => {
    console.log(`stage=${stage} records=${records}`);
  });

  const result = pipeline
    .pipe("grep ERROR", (records) =>
      records.filter((line) => /\bERROR\b/.test(line))
    )
    .pipe("awk route extraction", (records) =>
      records.flatMap((line) => {
        const match = line.match(/route=([^\s]+)/);
        return match ? [match[1]] : [];
      })
    )
    .pipe("unique", (records) => [...new Set(records)])
    .output();

  console.log("\nPipeline result:");
  result.forEach(console.log);

  console.log(
    "\nUnix pipes connect process streams. This in-process representation " +
    "shows the same compositional idea while EventEmitter exposes each stage."
  );
}

// ---------------------------------------------------------------------------
// Redirection
// ---------------------------------------------------------------------------

async function demoRedirection(workspace) {
  heading("redirection: stdout to a file");

  const logFile = path.join(workspace.logs, "application.log");
  const outputFile = path.join(workspace.reports, "errors.txt");

  const lines = (await fs.readFile(logFile, "utf8"))
    .split(/\r?\n/)
    .filter(Boolean);

  const errors = lines.filter((line) => /\bERROR\b/.test(line));

  // writeFile corresponds to replacement-style ">" redirection.
  await fs.writeFile(outputFile, errors.join("\n") + "\n", "utf8");

  console.log(`Created: ${outputFile}`);
  process.stdout.write(await fs.readFile(outputFile, "utf8"));

  // appendFile corresponds to ">>" redirection.
  await fs.appendFile(outputFile, "2026-10-02T06:10:30Z ERROR synthetic\n", "utf8");

  console.log("After append-style redirection:");
  process.stdout.write(await fs.readFile(outputFile, "utf8"));

  console.log(
    "\nNode streams make the same distinction explicit: replacing a file " +
    "opens it for a fresh write, while appending preserves existing bytes."
  );
}

// ---------------------------------------------------------------------------
// Real Linux pipeline
// ---------------------------------------------------------------------------

async function demoRealPipeline(workspace) {
  heading("Real Linux pipeline");

  if (process.platform === "win32") {
    console.log(
      "Skipped: this section requires a Unix-like environment with Linux CLI tools."
    );
    return;
  }

  const available = await Promise.all(
    ["grep", "awk", "sed"].map(commandExists)
  );

  if (!available.every(Boolean)) {
    console.log("Skipped because grep, awk, or sed is unavailable.");
    return;
  }

  /*
   * This uses explicit child processes rather than shell=true.
   * grep stdout is piped directly to awk stdin, and awk stdout becomes
   * sed stdin. No string interpolation is used to construct shell syntax.
   */
  const logPath = path.join(workspace.logs, "application.log");

  const grepProcess = spawn("grep", ["-E", "WARN|ERROR", logPath], {
    stdio: ["ignore", "pipe", "pipe"],
  });

  const awkProcess = spawn(
    "awk",
    [
      "{for(i=1;i<=NF;i++){if($i ~ /^route=/) route=$i;if($i ~ /^latency_ms=/) latency=$i} print route, latency}",
    ],
    {
      stdio: ["pipe", "pipe", "pipe"],
    }
  );

  const sedProcess = spawn(
    "sed",
    ["s/route=//;s/latency_ms=/latency_ms=/"],
    {
      stdio: ["pipe", "pipe", "pipe"],
    }
  );

  grepProcess.stdout.pipe(awkProcess.stdin);
  awkProcess.stdout.pipe(sedProcess.stdin);

  const [grepResult, awkResult, sedResult] = await Promise.all([
    collectChild(grepProcess),
    collectChild(awkProcess),
    collectChild(sedProcess),
  ]);

  if (grepResult.stderr) {
    process.stderr.write(grepResult.stderr);
  }

  if (awkResult.stderr) {
    process.stderr.write(awkResult.stderr);
  }

  if (sedResult.stderr) {
    process.stderr.write(sedResult.stderr);
  }

  console.log("Pipeline output:");
  process.stdout.write(sedResult.stdout);

  console.log(
    `Exit statuses: grep=${grepResult.code}, awk=${awkResult.code}, sed=${sedResult.code}`
  );
}

function collectChild(child) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");

    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });

    child.on("error", reject);
    child.on("close", (code, signal) => {
      resolve({ code, signal, stdout, stderr });
    });
  });
}

// ---------------------------------------------------------------------------
// Validation and security
// ---------------------------------------------------------------------------

async function demonstrateFailureModes(workspace) {
  heading("Failure modes, validation, and security");

  const missingFile = path.join(workspace.repository, "missing.txt");

  try {
    await fs.readFile(missingFile, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") {
      console.log("Handled missing file: ENOENT");
    } else {
      throw error;
    }
  }

  const malformed = "2026-10-02 ERROR route=/orders";
  const fields = malformed.trim().split(/\s+/);

  if (fields.length < 4) {
    console.log("Malformed log record rejected before field processing.");
  }

  const suspiciousInput = "ERROR; rm -rf /";

  /*
   * The value is treated only as data. It is never concatenated into a shell
   * command. This is the critical distinction between passing arguments to
   * spawn() and constructing a shell command string.
   */
  console.log(`Untrusted search term remains data: ${suspiciousInput}`);

  console.log(
    "\nAvoid child_process.exec() for untrusted command fragments. If a real "
    + "command is required, prefer spawn() with an argument array and shell:false."
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const workspace = await createWorkspace();

  try {
    console.log(`Linux CLI workspace: ${workspace.repository}`);

    await demoLs(workspace);
    await demoCd(workspace);
    await demoCat(workspace);
    await demoGrep(workspace);
    await demoFind(workspace);
    await demoAwk(workspace);
    await demoSed(workspace);
    await demoPipes(workspace);
    await demoRedirection(workspace);
    await demoRealPipeline(workspace);
    await demonstrateFailureModes(workspace);

    heading("Completed");
    console.log("The Linux CLI case study completed successfully.");
  } finally {
    await fs.rm(workspace.root, {
      recursive: true,
      force: true,
    });
  }
}

main().catch((error) => {
  console.error(`Fatal error: ${error.message}`);
  process.exitCode = 1;
});
