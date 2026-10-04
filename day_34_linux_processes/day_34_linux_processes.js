#!/usr/bin/env node

/**
 * Linux Processes in Node.js
 *
 * This program complements the Python laboratory by treating process
 * management as an event-driven problem. It demonstrates:
 *
 * - process identity
 * - child-process creation
 * - asynchronous process events
 * - background work
 * - signals
 * - process groups
 * - exit codes
 * - process-tree inspection through /proc
 * - supervision and timeouts
 * - safe argument handling
 *
 * Requires Linux and Node.js 18+.
 */

"use strict";

const {
  spawn,
  execFile,
} = require("node:child_process");

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

function requireLinux() {
  if (process.platform !== "linux") {
    throw new Error(
      "This program requires Linux because it reads /proc and uses POSIX signals."
    );
  }
}

function heading(title) {
  console.log(`\n${"=".repeat(78)}\n${title}\n${"=".repeat(78)}`);
}

function currentProcessIdentity() {
  heading("Node.js Process Identity");

  console.log(`PID:              ${process.pid}`);
  console.log(`Parent PID:       ${process.ppid}`);
  console.log(`Process platform: ${process.platform}`);
  console.log(`Node version:     ${process.version}`);
  console.log(`Executable:       ${process.execPath}`);
  console.log(`Working directory:${process.cwd()}`);
  console.log(`CPU count:        ${os.cpus().length}`);
}

function runChildNode(source, options = {}) {
  return spawn(process.execPath, ["-e", source], {
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  });
}

async function collectProcessOutput(child) {
  let stdout = "";
  let stderr = "";

  if (child.stdout) {
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
  }

  if (child.stderr) {
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
  }

  const result = await new Promise((resolve) => {
    child.once("error", (error) => {
      resolve({
        error,
        code: null,
        signal: null,
      });
    });

    child.once("exit", (code, signal) => {
      resolve({
        error: null,
        code,
        signal,
      });
    });
  });

  return {
    ...result,
    stdout,
    stderr,
  };
}

async function demonstrateChildProcess() {
  heading("Child Process and PID Relationship");

  const source = `
    console.log(JSON.stringify({
      pid: process.pid,
      ppid: process.ppid
    }));
  `;

  const child = runChildNode(source);
  console.log(`Parent PID: ${process.pid}`);
  console.log(`Spawned child PID: ${child.pid}`);

  const result = await collectProcessOutput(child);

  console.log(`Child output: ${result.stdout.trim()}`);
  console.log(`Exit code: ${result.code}`);
  console.log(`Termination signal: ${result.signal ?? "none"}`);
}

async function demonstrateBackgroundProcess() {
  heading("Background Process with Event-Driven Completion");

  const source = `
    let tick = 0;

    const timer = setInterval(() => {
      tick += 1;
      console.log(JSON.stringify({
        pid: process.pid,
        tick
      }));

      if (tick === 3) {
        clearInterval(timer);
        process.exit(0);
      }
    }, 300);
  `;

  const child = runChildNode(source);

  console.log(
    `Parent continues while background PID ${child.pid} performs asynchronous work.`
  );

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    process.stdout.write(`[background] ${chunk}`);
  });

  const result = await new Promise((resolve) => {
    child.once("error", (error) => resolve({ error }));
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });

  console.log(
    `Background process completed with code=${result.code}, signal=${result.signal ?? "none"}`
  );
}

async function demonstrateSignalHandling() {
  heading("Signals and Graceful Shutdown");

  const source = `
    let stopping = false;

    process.on("SIGTERM", () => {
      if (stopping) return;
      stopping = true;

      console.log("worker received SIGTERM");
      console.log("worker is releasing resources");
      setTimeout(() => process.exit(0), 150);
    });

    console.log(JSON.stringify({
      pid: process.pid,
      state: "ready"
    }));

    setInterval(() => {}, 1000);
  `;

  const child = runChildNode(source);

  child.stdout.setEncoding("utf8");

  const ready = await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("Timed out waiting for worker readiness.")),
      2000
    );

    child.stdout.on("data", (chunk) => {
      process.stdout.write(`[worker] ${chunk}`);

      if (chunk.includes('"state":"ready"')) {
        clearTimeout(timeout);
        resolve();
      }
    });

    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });

  void ready;

  console.log(`Sending SIGTERM to worker PID ${child.pid}`);
  child.kill("SIGTERM");

  const result = await collectProcessOutput(child);

  console.log(
    `Worker stopped with code=${result.code}, signal=${result.signal ?? "none"}`
  );
}

function readProcStatus(pid) {
  const statusPath = `/proc/${pid}/status`;

  try {
    const content = fs.readFileSync(statusPath, "utf8");
    const fields = {};

    for (const line of content.split("\n")) {
      const separator = line.indexOf(":");
      if (separator === -1) continue;

      const key = line.slice(0, separator);
      const value = line.slice(separator + 1).trim();
      fields[key] = value;
    }

    return fields;
  } catch {
    return null;
  }
}

function demonstrateProcInspection() {
  heading("Inspecting Linux Process Metadata through /proc");

  const status = readProcStatus(process.pid);

  if (!status) {
    console.log("Current process disappeared or /proc is unavailable.");
    return;
  }

  for (const field of [
    "Name",
    "State",
    "Pid",
    "PPid",
    "Threads",
    "VmRSS",
    "Uid",
    "SigBlk",
    "SigIgn",
    "SigCgt",
  ]) {
    console.log(`${field.padEnd(10)}: ${status[field] ?? "unavailable"}`);
  }
}

function readProcessInventory() {
  const entries = fs.readdirSync("/proc", { withFileTypes: true });

  return entries
    .filter((entry) => entry.isDirectory() && /^\d+$/.test(entry.name))
    .map((entry) => {
      const pid = Number(entry.name);
      const status = readProcStatus(pid);

      if (!status) return null;

      const ppid = Number.parseInt(status.PPid ?? "0", 10);

      return {
        pid,
        ppid: Number.isFinite(ppid) ? ppid : 0,
        name: status.Name ?? "?",
        state: status.State ?? "?",
      };
    })
    .filter(Boolean);
}

function buildProcessTree(records) {
  const children = new Map();

  for (const record of records) {
    if (!children.has(record.ppid)) {
      children.set(record.ppid, []);
    }

    children.get(record.ppid).push(record);
  }

  for (const siblings of children.values()) {
    siblings.sort((a, b) => a.pid - b.pid);
  }

  return children;
}

function printProcessTree(children, parentPid, prefix = "", depth = 0) {
  if (depth >= 3) return;

  const siblings = children.get(parentPid) ?? [];

  siblings.forEach((record, index) => {
    const last = index === siblings.length - 1;
    const branch = last ? "└── " : "├── ";

    console.log(
      `${prefix}${branch}${record.pid} ${record.name} [${record.state}]`
    );

    printProcessTree(
      children,
      record.pid,
      prefix + (last ? "    " : "│   "),
      depth + 1
    );
  });
}

function demonstrateProcessTree() {
  heading("Real Linux Process Tree");

  const records = readProcessInventory();
  const children = buildProcessTree(records);
  const current = records.find((record) => record.pid === process.pid);

  if (!current) {
    console.log("Current process was not present in the /proc snapshot.");
    return;
  }

  console.log(
    `Current PID=${current.pid}, PPID=${current.ppid}, Name=${current.name}`
  );

  console.log(`Processes descended from PPID ${current.ppid}:`);
  printProcessTree(children, current.ppid);
}

async function demonstrateTimeout() {
  heading("Process Supervision and Timeout");

  const source = `
    console.log("slow worker started", process.pid);
    setInterval(() => {}, 1000);
  `;

  const child = runChildNode(source);
  let timedOut = false;

  const completion = new Promise((resolve) => {
    child.once("error", (error) => resolve({ error }));
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });

  const timeout = setTimeout(() => {
    timedOut = true;
    console.log(`Worker PID ${child.pid} exceeded its deadline.`);
    child.kill("SIGTERM");
  }, 700);

  const result = await completion;
  clearTimeout(timeout);

  if (result.error) {
    console.log(`Worker error: ${result.error.message}`);
    return;
  }

  console.log(
    `Worker stopped: code=${result.code}, signal=${result.signal ?? "none"}, timeout=${timedOut}`
  );
}

async function demonstrateProcessGroup() {
  heading("Process Groups and Group Termination");

  /*
   * detached:true asks Node to create the child in a new process group on
   * platforms that support it. On Linux, the child's PID can be used as the
   * process-group ID for kill(-pid, signal).
   */
  const source = `
    const { spawn } = require("node:child_process");

    const grandchild = spawn(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)"],
      { stdio: "ignore" }
    );

    console.log(JSON.stringify({
      parent: process.pid,
      grandchild: grandchild.pid
    }));

    setInterval(() => {}, 1000);
  `;

  const child = runChildNode(source, {
    detached: true,
  });

  child.stdout.setEncoding("utf8");

  const firstOutput = await new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("Timed out waiting for process group.")),
      2000
    );

    child.stdout.once("data", (chunk) => {
      clearTimeout(timeout);
      resolve(chunk.trim());
    });

    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });

  console.log(`Process-group member report: ${firstOutput}`);
  console.log(`Process-group leader PID: ${child.pid}`);

  try {
    /*
     * Negative PID means "send the signal to the process group whose ID is
     * abs(PID)" when using the POSIX kill command/API semantics.
     */
    process.kill(-child.pid, "SIGTERM");
    console.log(`SIGTERM sent to process group ${child.pid}.`);
  } catch (error) {
    console.log(`Could not terminate process group: ${error.message}`);
    child.kill("SIGKILL");
  }

  await collectProcessOutput(child);
}

async function demonstrateSafeCommandExecution() {
  heading("Safe Command Execution");

  /*
   * execFile() does not invoke a shell by default. Arguments are passed as
   * argument-vector entries, preventing shell metacharacters in an input value
   * from becoming executable syntax.
   */
  const fileName = path.join(os.tmpdir(), `linux-process-${process.pid}.txt`);

  fs.writeFileSync(
    fileName,
    "process tree\nsignals\nbackground process\n",
    "utf8"
  );

  await new Promise((resolve) => {
    execFile(
      "wc",
      ["-l", fileName],
      { encoding: "utf8" },
      (error, stdout, stderr) => {
        if (error) {
          console.error(`wc failed: ${error.message}`);
          if (stderr) console.error(stderr.trim());
        } else {
          console.log(`wc output: ${stdout.trim()}`);
        }

        fs.rmSync(fileName, { force: true });
        resolve();
      }
    );
  });
}

async function demonstrateExitCodes() {
  heading("Exit Codes and Signals");

  const successful = runChildNode("process.exit(0)");
  const failed = runChildNode("process.exit(23)");

  const successResult = await collectProcessOutput(successful);
  const failureResult = await collectProcessOutput(failed);

  console.log(`Successful child exit code: ${successResult.code}`);
  console.log(`Failed child exit code: ${failureResult.code}`);

  const killed = runChildNode("setInterval(() => {}, 1000)");

  await new Promise((resolve) => setTimeout(resolve, 100));
  killed.kill("SIGTERM");

  const killedResult = await collectProcessOutput(killed);

  console.log(
    `Signal-terminated child: code=${killedResult.code}, signal=${killedResult.signal}`
  );
}

async function demonstrateSignalState() {
  heading("Signal State");

  const status = readProcStatus(process.pid);

  for (const field of [
    "SigQ",
    "SigPnd",
    "ShdPnd",
    "SigBlk",
    "SigIgn",
    "SigCgt",
  ]) {
    console.log(`${field.padEnd(8)}: ${status?.[field] ?? "unavailable"}`);
  }
}

async function runAll() {
  requireLinux();

  currentProcessIdentity();
  await demonstrateChildProcess();
  await demonstrateBackgroundProcess();
  await demonstrateSignalHandling();
  demonstrateProcInspection();
  demonstrateProcessTree();
  await demonstrateTimeout();
  await demonstrateProcessGroup();
  await demonstrateSafeCommandExecution();
  await demonstrateExitCodes();
  await demonstrateSignalState();
}

async function main() {
  const command = process.argv[2] ?? "all";

  const commands = {
    identity: async () => currentProcessIdentity(),
    child: demonstrateChildProcess,
    background: demonstrateBackgroundProcess,
    signals: demonstrateSignalHandling,
    proc: async () => demonstrateProcInspection(),
    tree: async () => demonstrateProcessTree(),
    timeout: demonstrateTimeout,
    groups: demonstrateProcessGroup,
    safe: demonstrateSafeCommandExecution,
    exits: demonstrateExitCodes,
    signalState: demonstrateSignalState,
    all: runAll,
  };

  if (!(command in commands)) {
    console.error(
      `Unknown command "${command}". Available commands: ${Object.keys(commands).join(", ")}`
    );
    process.exitCode = 2;
    return;
  }

  try {
    await commands[command]();
  } catch (error) {
    console.error(`Process laboratory failed: ${error.message}`);
    process.exitCode = 1;
  }
}

process.on("SIGINT", () => {
  console.log("\nReceived SIGINT. Exiting the supervisor cleanly.");
  process.exit(130);
});

main();
