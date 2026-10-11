"use strict";

/*
 * Windows Fundamentals laboratory.
 *
 * Runtime: Node.js 18 or later.
 * Read-only inspection commands are executed only on Windows.
 * Filesystem exercises use an isolated temporary directory.
 * No external npm dependencies are required.
 */

const os = require("node:os");
const fs = require("node:fs/promises");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { randomUUID } = require("node:crypto");
const { promisify } = require("node:util");

const WINDOWS = process.platform === "win32";
const execFile = promisify(spawnCompatibleExecFile);

function spawnCompatibleExecFile(file, args, options, callback) {
  const child = spawn(file, args, {
    ...options,
    shell: false,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  let settled = false;

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");

  child.stdout.on("data", chunk => {
    stdout += chunk;
  });

  child.stderr.on("data", chunk => {
    stderr += chunk;
  });

  child.on("error", error => {
    if (settled) return;
    settled = true;
    callback(error);
  });

  child.on("close", (code, signal) => {
    if (settled) return;
    settled = true;

    const error = code === 0
      ? null
      : Object.assign(
          new Error(stderr || `Process exited with code ${code}`),
          { code, signal }
        );

    callback(error, stdout, stderr);
  });
}

function heading(text) {
  console.log(`\n${"=".repeat(72)}\n${text}\n${"=".repeat(72)}`);
}

function validateServiceName(name) {
  if (
    typeof name !== "string" ||
    !/^[A-Za-z0-9_.-]{1,256}$/.test(name)
  ) {
    throw new TypeError("Service names must contain only safe identifier characters.");
  }
  return name;
}

async function runCommand(executable, args, timeoutMs = 15000) {
  try {
    const result = await Promise.race([
      execFile(executable, args, {
        timeout: timeoutMs,
        maxBuffer: 2 * 1024 * 1024,
        windowsHide: true,
      }),
      new Promise((_, reject) => {
        const timer = setTimeout(
          () => reject(new Error("Command timed out")),
          timeoutMs
        );
        timer.unref?.();
      }),
    ]);

    return { ok: true, stdout: result[1].trim(), stderr: result[2].trim() };
  } catch (error) {
    return {
      ok: false,
      stdout: "",
      stderr: error.message,
      exitCode: error.code ?? null,
    };
  }
}

function describeArchitecture() {
  const release = os.release();
  const architecture = os.arch();

  return {
    platform: process.platform,
    release,
    hostname: os.hostname(),
    nodeProcessArchitecture: architecture,
    cpuCount: os.cpus().length,
    totalMemoryBytes: os.totalmem(),
    freeMemoryBytes: os.freemem(),
    uptimeSeconds: os.uptime(),
    architectureNote:
      "Node reports the architecture of its own process. It does not, by itself, " +
      "prove the native architecture of Windows.",
  };
}

async function inspectIdentity() {
  const identity = {
    username: os.userInfo().username,
    homeDirectory: os.homedir(),
    environmentDomain: process.env.USERDOMAIN ?? null,
    systemDrive: process.env.SystemDrive ?? null,
    profileDirectory: process.env.USERPROFILE ?? null,
  };

  if (WINDOWS) {
    identity.token = await runCommand("whoami.exe", ["/all"]);
  }

  return identity;
}

async function inspectService(name) {
  validateServiceName(name);

  if (!WINDOWS) {
    return { available: false, reason: "Windows-only service inspection" };
  }

  const query = await runCommand("sc.exe", ["queryex", name]);
  const configuration = await runCommand("sc.exe", ["qc", name]);

  return { name, query, configuration };
}

async function inspectServices() {
  if (!WINDOWS) {
    return { available: false, reason: "Windows-only service inspection" };
  }

  // PowerShell receives a fixed script; user-controlled values are not
  // interpolated into executable PowerShell source.
  const script =
    "Get-CimInstance Win32_Service | " +
    "Select-Object Name,DisplayName,State,StartMode,StartName | " +
    "ConvertTo-Json -Compress";

  const result = await runCommand(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    30000
  );

  if (!result.ok) return result;

  try {
    const parsed = JSON.parse(result.stdout);
    const services = Array.isArray(parsed) ? parsed : [parsed];

    return {
      ok: true,
      count: services.length,
      services: services
        .sort((a, b) => a.Name.localeCompare(b.Name))
        .slice(0, 30),
    };
  } catch (error) {
    return {
      ok: false,
      error: `Unable to parse service inventory: ${error.message}`,
      rawOutput: result.stdout.slice(0, 4000),
    };
  }
}

async function inspectLocalAccounts() {
  if (!WINDOWS) {
    return { available: false, reason: "Windows-only account inspection" };
  }

  const [users, groups] = await Promise.all([
    runCommand("net.exe", ["user"]),
    runCommand("net.exe", ["localgroup"]),
  ]);

  return { users, groups };
}

async function inspectRegistry() {
  if (!WINDOWS) {
    return { available: false, reason: "Windows-only registry inspection" };
  }

  // reg.exe query is used only for reading selected keys.
  const queries = [
    [
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      ["/v", "ProductName"],
    ],
    [
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
      ["/v", "CurrentBuild"],
    ],
    [
      "HKCU\\Environment",
      [],
    ],
  ];

  const results = [];

  for (const [key, extraArgs] of queries) {
    results.push({
      key,
      result: await runCommand("reg.exe", ["query", key, ...extraArgs]),
    });
  }

  return results;
}

async function filesystemLaboratory() {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), `windows-lab-${randomUUID()}-`)
  );

  try {
    const applicationDirectory = path.join(root, "Application");
    const logsDirectory = path.join(root, "Logs");

    await Promise.all([
      fs.mkdir(applicationDirectory),
      fs.mkdir(logsDirectory),
    ]);

    const configurationPath = path.join(
      applicationDirectory,
      "settings.json"
    );
    const logPath = path.join(logsDirectory, "events.log");

    await fs.writeFile(
      configurationPath,
      JSON.stringify(
        {
          serviceName: "InventoryAgent",
          environment: "training",
          logLevel: "information",
        },
        null,
        2
      ),
      { encoding: "utf8", flag: "wx" }
    );

    await fs.writeFile(
      logPath,
      "service=InventoryAgent event=initialized\n" +
      "service=InventoryAgent event=configuration_loaded\n",
      { encoding: "utf8", flag: "wx" }
    );

    const configuration = JSON.parse(
      await fs.readFile(configurationPath, "utf8")
    );

    const metadata = await fs.stat(configurationPath);
    const entries = await fs.readdir(root, { withFileTypes: true });

    // Path containment must use resolved paths, not only string prefixes.
    const resolvedRoot = await fs.realpath(root);
    const resolvedConfiguration = await fs.realpath(configurationPath);
    const relative = path.relative(resolvedRoot, resolvedConfiguration);

    if (
      relative === ".." ||
      relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)
    ) {
      throw new Error("Resolved configuration path escaped the laboratory root.");
    }

    return {
      root,
      configuration,
      fileSizeBytes: metadata.size,
      createdEntries: entries.map(entry => ({
        name: entry.name,
        isDirectory: entry.isDirectory(),
      })),
      logLines: (await fs.readFile(logPath, "utf8"))
        .trim()
        .split(/\r?\n/),
      pathContainedWithinRoot: true,
      directoryTraversalExample:
        "A resolved-path check detects paths that escape a trusted root.",
    };
  } finally {
    // Recursive deletion is restricted to the exact temporary directory
    // created by this function.
    await fs.rm(root, { recursive: true, force: true });
  }
}

function explainSecurityBoundaries() {
  return {
    architecture:
      "User-mode applications request privileged operations through operating-system interfaces.",
    usersAndGroups:
      "Access tokens carry user and group SIDs, privileges, and other security information.",
    services:
      "Service configuration and the identity running a service determine its operational exposure.",
    registry:
      "Registry keys have security descriptors, and 32-bit and 64-bit registry views can differ.",
    filesystem:
      "File access depends on security descriptors and requested access, not merely file existence.",
    policy:
      "A successful metadata query is not proof that an operation is authorized.",
  };
}

async function main() {
  heading("Windows architecture");
  console.log(JSON.stringify(describeArchitecture(), null, 2));

  heading("Current identity");
  console.log(JSON.stringify(await inspectIdentity(), null, 2));

  heading("Security boundaries");
  console.log(JSON.stringify(explainSecurityBoundaries(), null, 2));

  heading("Filesystem laboratory");
  console.log(JSON.stringify(await filesystemLaboratory(), null, 2));

  if (WINDOWS) {
    heading("Local accounts and groups");
    console.log(JSON.stringify(await inspectLocalAccounts(), null, 2));

    heading("Selected registry values");
    console.log(JSON.stringify(await inspectRegistry(), null, 2));

    heading("Service inventory");
    console.log(JSON.stringify(await inspectServices(), null, 2));

    heading("Service configuration example");
    console.log(JSON.stringify(await inspectService("EventLog"), null, 2));
  } else {
    console.log(
      "\nWindows-specific account, service, and registry queries were skipped."
    );
  }
}

main().catch(error => {
  console.error("Laboratory execution failed:", error.message);
  process.exitCode = 1;
});
