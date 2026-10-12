"use strict";

/*
 * Windows process lifecycle and service correlation model.
 *
 * Run:
 *   node windows-processes.js
 *   node windows-processes.js --live
 *   node windows-processes.js --services
 *
 * Live inspection uses PowerShell and read-only CIM queries. The sample model
 * runs on any Node.js platform and makes no changes to the operating system.
 */

const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const { performance } = require("node:perf_hooks");

class ProcessRecord {
    constructor({
        pid,
        name,
        parentPid = null,
        threadCount = 0,
        executablePath = null,
        commandLine = null,
        observedAt = Date.now(),
    }) {
        if (!Number.isSafeInteger(pid) || pid <= 0) {
            throw new TypeError(`Invalid process ID: ${pid}`);
        }
        if (!Number.isSafeInteger(threadCount) || threadCount < 0) {
            throw new TypeError(`Invalid thread count: ${threadCount}`);
        }
        if (parentPid !== null &&
            (!Number.isSafeInteger(parentPid) || parentPid < 0)) {
            throw new TypeError(`Invalid parent process ID: ${parentPid}`);
        }

        this.pid = pid;
        this.name = String(name || "unknown");
        this.parentPid = parentPid;
        this.threadCount = threadCount;
        this.executablePath = executablePath;
        this.commandLine = commandLine;
        this.observedAt = observedAt;
        this.children = [];
    }
}

class ProcessGraph {
    constructor(records) {
        this.byPid = new Map();

        for (const record of records) {
            if (!(record instanceof ProcessRecord)) {
                throw new TypeError("ProcessGraph requires ProcessRecord instances");
            }
            if (this.byPid.has(record.pid)) {
                throw new Error(`Duplicate PID ${record.pid}`);
            }
            this.byPid.set(record.pid, record);
        }

        this.rebuildChildren();
    }

    rebuildChildren() {
        for (const process of this.byPid.values()) {
            process.children = [];
        }

        for (const process of this.byPid.values()) {
            const parent = this.byPid.get(process.parentPid);
            if (parent) {
                parent.children.push(process.pid);
            }
        }

        for (const process of this.byPid.values()) {
            process.children.sort((left, right) => {
                const a = this.byPid.get(left).name.toLowerCase();
                const b = this.byPid.get(right).name.toLowerCase();
                return a.localeCompare(b) || left - right;
            });
        }
    }

    roots() {
        return [...this.byPid.values()]
            .filter(process => !this.byPid.has(process.parentPid))
            .sort((a, b) => a.pid - b.pid);
    }

    descendants(pid) {
        if (!this.byPid.has(pid)) {
            throw new Error(`PID ${pid} does not exist in this snapshot`);
        }

        const result = [];
        const queue = [...this.byPid.get(pid).children];
        const visited = new Set([pid]);
        let cursor = 0;

        // A cursor avoids repeatedly shifting an array, which can be costly
        // for large process inventories.
        while (cursor < queue.length) {
            const childPid = queue[cursor++];
            if (visited.has(childPid)) {
                continue;
            }

            visited.add(childPid);
            const child = this.byPid.get(childPid);
            if (!child) {
                continue;
            }

            result.push(child);
            queue.push(...child.children);
        }

        return result;
    }

    renderTree() {
        const lines = [];
        const visited = new Set();

        for (const root of this.roots()) {
            const stack = [{
                pid: root.pid,
                prefix: "",
                last: true,
            }];

            while (stack.length > 0) {
                const { pid, prefix, last } = stack.pop();
                if (visited.has(pid)) {
                    lines.push(`${prefix}[repeated PID ${pid}]`);
                    continue;
                }

                visited.add(pid);
                const process = this.byPid.get(pid);
                lines.push(
                    `${prefix}${last ? "└──" : "├──"} ${process.name}` +
                    ` (PID ${pid}, threads=${process.threadCount})`
                );

                const childPrefix = prefix + (last ? "    " : "│   ");
                const children = process.children;
                for (let index = children.length - 1; index >= 0; index--) {
                    stack.push({
                        pid: children[index],
                        prefix: childPrefix,
                        last: index === children.length - 1,
                    });
                }
            }
        }

        // A malformed cycle has no root. Expose it instead of silently omitting it.
        for (const pid of this.byPid.keys()) {
            if (!visited.has(pid)) {
                lines.push(`[unreachable or cyclic component at PID ${pid}]`);
                const stack = [pid];

                while (stack.length > 0) {
                    const currentPid = stack.pop();
                    if (visited.has(currentPid)) {
                        continue;
                    }

                    visited.add(currentPid);
                    const process = this.byPid.get(currentPid);
                    lines.push(`    ${process.name} (PID ${currentPid})`);
                    stack.push(...process.children);
                }
            }
        }

        return lines;
    }

    summary() {
        const processes = [...this.byPid.values()];
        return {
            processCount: processes.length,
            reportedThreadCount: processes.reduce(
                (total, process) => total + process.threadCount, 0
            ),
            rootCount: this.roots().length,
            topThreadConsumers: processes
                .toSorted((a, b) => b.threadCount - a.threadCount)
                .slice(0, 8)
                .map(({ pid, name, threadCount }) => ({
                    pid,
                    name,
                    threadCount,
                })),
        };
    }
}

function makeSampleGraph() {
    return new ProcessGraph([
        new ProcessRecord({ pid: 4, name: "System", threadCount: 180 }),
        new ProcessRecord({
            pid: 620, name: "services.exe", parentPid: 4, threadCount: 12,
        }),
        new ProcessRecord({
            pid: 840, name: "svchost.exe", parentPid: 620, threadCount: 28,
        }),
        new ProcessRecord({
            pid: 960, name: "svchost.exe", parentPid: 620, threadCount: 34,
        }),
        new ProcessRecord({
            pid: 1200, name: "explorer.exe", parentPid: 620, threadCount: 42,
        }),
        new ProcessRecord({
            pid: 1300, name: "notepad.exe", parentPid: 1200, threadCount: 8,
        }),
        new ProcessRecord({
            pid: 1450, name: "powershell.exe", parentPid: 1200, threadCount: 14,
        }),
        new ProcessRecord({
            pid: 1500, name: "python.exe", parentPid: 1450, threadCount: 6,
        }),
        new ProcessRecord({
            pid: 1700, name: "chrome.exe", parentPid: 1200, threadCount: 31,
        }),
        new ProcessRecord({
            pid: 1710, name: "chrome.exe", parentPid: 1700, threadCount: 16,
        }),
        new ProcessRecord({
            pid: 1720, name: "chrome.exe", parentPid: 1700, threadCount: 22,
        }),
    ]);
}

function findPowerShell() {
    if (process.platform !== "win32") {
        throw new Error("Live Windows queries require Windows");
    }

    const candidates = [
        path.join(
            process.env.SystemRoot || "C:\\Windows",
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe"
        ),
        "pwsh.exe",
    ];

    // The first candidate is an explicit Windows path; a missing executable
    // falls back to pwsh.exe through PATH resolution.
    return candidates[0];
}

function runPowerShellJson(script, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
        const executable = findPowerShell();
        const child = spawn(
            executable,
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "RemoteSigned",
                "-Command",
                script,
            ],
            {
                windowsHide: true,
                stdio: ["ignore", "pipe", "pipe"],
            }
        );

        let stdout = "";
        let stderr = "";
        let settled = false;
        const timeout = setTimeout(() => {
            if (!settled) {
                child.kill();
                settled = true;
                reject(new Error("PowerShell query timed out"));
            }
        }, timeoutMs);

        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", chunk => {
            stdout += chunk;
            if (stdout.length > 30 * 1024 * 1024) {
                child.kill();
                if (!settled) {
                    settled = true;
                    clearTimeout(timeout);
                    reject(new Error("PowerShell output exceeded the size limit"));
                }
            }
        });
        child.stderr.on("data", chunk => {
            stderr += chunk;
            if (stderr.length > 1024 * 1024) {
                stderr = stderr.slice(-1024 * 1024);
            }
        });

        child.on("error", error => {
            if (!settled) {
                settled = true;
                clearTimeout(timeout);
                reject(error);
            }
        });

        child.on("close", code => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(timeout);

            if (code !== 0) {
                reject(new Error(`PowerShell exited with code ${code}: ${stderr}`));
                return;
            }

            try {
                const parsed = JSON.parse(stdout.trim() || "[]");
                resolve(Array.isArray(parsed) ? parsed : [parsed]);
            } catch (error) {
                reject(new Error(`Unable to parse PowerShell JSON: ${error.message}`));
            }
        });
    });
}

async function collectProcesses() {
    const query = [
        "$ErrorActionPreference = 'Stop'",
        "$items = Get-CimInstance Win32_Process |",
        "Select-Object ProcessId, ParentProcessId, Name, ThreadCount, ExecutablePath, CommandLine",
        "$items | ConvertTo-Json -Depth 4 -Compress",
    ].join("; ");

    const raw = await runPowerShellJson(query);
    return raw.map(item => new ProcessRecord({
        pid: Number(item.ProcessId),
        name: item.Name,
        parentPid: item.ParentProcessId == null
            ? null
            : Number(item.ParentProcessId),
        threadCount: Number(item.ThreadCount || 0),
        executablePath: item.ExecutablePath || null,
        commandLine: item.CommandLine || null,
    }));
}

async function collectServices() {
    const query = [
        "$ErrorActionPreference = 'Stop'",
        "$items = Get-CimInstance Win32_Service |",
        "Select-Object Name, DisplayName, State, StartMode, ProcessId, StartName",
        "$items | ConvertTo-Json -Depth 4 -Compress",
    ].join("; ");

    return runPowerShellJson(query);
}

function correlateServices(services, graph) {
    return services.map(service => {
        const pid = Number(service.ProcessId || 0);
        const process = graph.byPid.get(pid);
        return {
            name: service.Name,
            displayName: service.DisplayName,
            state: service.State,
            startMode: service.StartMode,
            pid: pid || null,
            processName: process ? process.name : null,
            processObserved: Boolean(process),
        };
    });
}

async function writeReport(destination, graph, services) {
    const report = {
        generatedAt: new Date().toISOString(),
        platform: os.platform(),
        summary: graph.summary(),
        processes: [...graph.byPid.values()],
        services: services || [],
    };

    const resolved = path.resolve(destination);
    await fs.mkdir(path.dirname(resolved), { recursive: true });

    // Rename within the destination directory so readers do not observe a
    // partially written JSON report.
    const temporary = `${resolved}.${process.pid}.tmp`;
    try {
        await fs.writeFile(
            temporary,
            `${JSON.stringify(report, null, 2)}\n`,
            { encoding: "utf8", flag: "wx" }
        );
        await fs.rename(temporary, resolved);
    } catch (error) {
        await fs.rm(temporary, { force: true }).catch(() => {});
        throw error;
    }
}

function parseArguments(argv) {
    const options = {
        live: false,
        services: false,
        tree: false,
        json: null,
        pid: null,
    };

    for (let index = 0; index < argv.length; index++) {
        const argument = argv[index];

        if (argument === "--live") options.live = true;
        else if (argument === "--services") options.services = true;
        else if (argument === "--tree") options.tree = true;
        else if (argument === "--json") {
            options.json = argv[++index];
            if (!options.json) throw new Error("--json requires a path");
        } else if (argument === "--pid") {
            options.pid = Number(argv[++index]);
            if (!Number.isSafeInteger(options.pid) || options.pid <= 0) {
                throw new Error("--pid requires a positive integer");
            }
        } else if (argument === "--help") {
            console.log(
                "Usage: node windows-processes.js [--live] [--tree] " +
                "[--services] [--pid PID] [--json PATH]"
            );
            process.exit(0);
        } else {
            throw new Error(`Unknown argument: ${argument}`);
        }
    }

    return options;
}

async function main() {
    const options = parseArguments(process.argv.slice(2));
    const started = performance.now();

    let graph;
    if (options.live) {
        graph = new ProcessGraph(await collectProcesses());
    } else {
        graph = makeSampleGraph();
        console.log("Using sample process data. Pass --live on Windows for live data.");
    }

    console.log("\nProcess inventory");
    console.log(JSON.stringify(graph.summary(), null, 2));

    if (options.tree) {
        console.log("\nParent-child tree");
        console.log(graph.renderTree().join("\n"));
    }

    if (options.pid !== null) {
        const descendants = graph.descendants(options.pid);
        console.log(`\nDescendants of PID ${options.pid}`);
        for (const process of descendants) {
            console.log(`${process.pid}\t${process.name}\tthreads=${process.threadCount}`);
        }
    }

    let services = [];
    if (options.services) {
        services = await collectServices();
        console.log("\nService-to-process correlation");
        console.log(JSON.stringify(correlateServices(services, graph), null, 2));
    }

    if (options.json) {
        await writeReport(options.json, graph, services);
        console.log(`\nReport saved to ${path.resolve(options.json)}`);
    }

    console.log(`\nElapsed: ${(performance.now() - started).toFixed(2)} ms`);
}

main().catch(error => {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
});
