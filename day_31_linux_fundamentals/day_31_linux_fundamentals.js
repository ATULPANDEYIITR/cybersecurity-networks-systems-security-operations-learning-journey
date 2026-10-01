#!/usr/bin/env node
"use strict";

/*
 * Linux Fundamentals: event-driven systems model
 *
 * This Node.js program complements the Python implementation by modeling
 * Linux administration as an event-driven workflow. It focuses on:
 * filesystem metadata, identity and permissions, process lifecycle,
 * package dependencies, and service supervision.
 *
 * The program does not modify the host system and requires no npm packages.
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const { EventEmitter } = require("node:events");

const execFileAsync = promisify(execFile);


// ---------------------------------------------------------------------------
// Filesystem metadata
// ---------------------------------------------------------------------------

function modeToPermissionText(mode) {
    const bits = [
        [0o400, "r"], [0o200, "w"], [0o100, "x"],
        [0o040, "r"], [0o020, "w"], [0o010, "x"],
        [0o004, "r"], [0o002, "w"], [0o001, "x"],
    ];

    return bits
        .map(([bit, character]) => (mode & bit ? character : "-"))
        .join("");
}

function modeToOctal(mode) {
    return (mode & 0o7777).toString(8).padStart(4, "0");
}

function describeFilesystemEntry(targetPath) {
    /*
     * lstat-style behavior is important for symbolic links: we inspect the
     * directory entry itself instead of silently following the target.
     */
    const metadata = fs.lstatSync(targetPath);

    let type = "other";
    if (metadata.isFile()) type = "regular file";
    else if (metadata.isDirectory()) type = "directory";
    else if (metadata.isSymbolicLink()) type = "symbolic link";
    else if (metadata.isSocket()) type = "socket";
    else if (metadata.isFIFO()) type = "FIFO";

    return {
        path: targetPath,
        type,
        permissions: modeToPermissionText(metadata.mode),
        octal: modeToOctal(metadata.mode),
        uid: metadata.uid,
        gid: metadata.gid,
        size: metadata.size,
    };
}


// ---------------------------------------------------------------------------
// Users, groups, and permission decisions
// ---------------------------------------------------------------------------

class Identity {
    constructor(username, uid, groups = []) {
        this.username = username;
        this.uid = uid;
        this.groups = new Set(groups);
    }

    hasGroup(groupName) {
        return this.groups.has(groupName);
    }
}

class UnixInode {
    constructor(name, owner, group, mode, directory = false) {
        this.name = name;
        this.owner = owner;
        this.group = group;
        this.mode = mode;
        this.directory = directory;
    }

    permissionClass(identity) {
        if (identity.username === this.owner) {
            return "owner";
        }

        if (identity.hasGroup(this.group)) {
            return "group";
        }

        return "other";
    }

    can(identity, operation) {
        const permissionBits = {
            read: 4,
            write: 2,
            execute: 1,
        };

        if (!(operation in permissionBits)) {
            throw new TypeError("Unsupported permission operation");
        }

        const selectedClass = this.permissionClass(identity);
        const shifts = {
            owner: 6,
            group: 3,
            other: 0,
        };

        const bit = permissionBits[operation] << shifts[selectedClass];
        return Boolean(this.mode & bit);
    }
}

function permissionWorkflow() {
    console.log("\n=== Permission Decision Engine ===");

    const developer = new Identity(
        "developer",
        1001,
        ["developers", "webops"]
    );

    const auditor = new Identity(
        "auditor",
        1002,
        ["auditors"]
    );

    const config = new UnixInode(
        "/etc/web-monitor/config",
        "root",
        "webops",
        0o640
    );

    for (const identity of [developer, auditor]) {
        console.log(
            `${identity.username}: class=${config.permissionClass(identity)}, ` +
            `read=${config.can(identity, "read")}, ` +
            `write=${config.can(identity, "write")}`
        );
    }

    /*
     * Directory permissions differ from regular-file permissions:
     * read controls directory entry listing, while write controls modification
     * of entries and execute controls traversal through the directory.
     */
    const projectDirectory = new UnixInode(
        "/srv/project",
        "root",
        "developers",
        0o2775,
        true
    );

    console.log(
        `Directory ${projectDirectory.name}: ` +
        `mode=${modeToOctal(projectDirectory.mode)}, ` +
        `developer traversal=${projectDirectory.can(developer, "execute")}`
    );
}


// ---------------------------------------------------------------------------
// Process lifecycle as an event-driven model
// ---------------------------------------------------------------------------

class ProcessManager extends EventEmitter {
    constructor() {
        super();
        this.processes = new Map();
        this.nextPid = 4000;
    }

    spawn(command, user) {
        const process = {
            pid: this.nextPid++,
            command,
            user,
            state: "running",
            startedAt: new Date(),
            exitCode: null,
        };

        this.processes.set(process.pid, process);
        this.emit("spawn", process);
        return process;
    }

    terminate(pid, exitCode = 0) {
        const process = this.processes.get(pid);

        if (!process) {
            throw new Error(`PID ${pid} does not exist`);
        }

        if (process.state !== "running") {
            return;
        }

        process.state = "exited";
        process.exitCode = exitCode;
        process.endedAt = new Date();

        this.emit("exit", process);
    }
}

function processLifecycleWorkflow() {
    console.log("\n=== Event-Driven Process Lifecycle ===");

    const manager = new ProcessManager();

    manager.on("spawn", (process) => {
        console.log(
            `spawn: PID=${process.pid} user=${process.user} ` +
            `command=${process.command}`
        );
    });

    manager.on("exit", (process) => {
        console.log(
            `exit: PID=${process.pid} code=${process.exitCode} ` +
            `state=${process.state}`
        );
    });

    const worker = manager.spawn("/usr/local/bin/report-worker", "reporter");
    manager.terminate(worker.pid, 0);

    try {
        manager.terminate(worker.pid);
    } catch (error) {
        console.log(`unexpected lifecycle error: ${error.message}`);
    }
}


// ---------------------------------------------------------------------------
// Package dependency graph
// ---------------------------------------------------------------------------

class PackageRepository {
    constructor(packages) {
        this.packages = new Map(
            packages.map((pkg) => [pkg.name, pkg])
        );
    }

    resolve(rootPackage) {
        const ordered = [];
        const visiting = new Set();
        const visited = new Set();

        const visit = (name) => {
            if (visited.has(name)) return;

            if (visiting.has(name)) {
                throw new Error(`dependency cycle detected at ${name}`);
            }

            const pkg = this.packages.get(name);
            if (!pkg) {
                throw new Error(`package ${name} is unavailable`);
            }

            visiting.add(name);

            for (const dependency of pkg.dependencies) {
                visit(dependency);
            }

            visiting.delete(name);
            visited.add(name);
            ordered.push(pkg);
        };

        visit(rootPackage);
        return ordered;
    }
}

function packageWorkflow() {
    console.log("\n=== Package Dependency Graph ===");

    const repository = new PackageRepository([
        {
            name: "libcrypto",
            version: "4.1",
            dependencies: [],
        },
        {
            name: "http-client",
            version: "8.5",
            dependencies: ["libcrypto"],
        },
        {
            name: "monitor-agent",
            version: "2.8",
            dependencies: ["http-client"],
        },
    ]);

    const installationPlan = repository.resolve("monitor-agent");

    for (const pkg of installationPlan) {
        console.log(
            `${pkg.name}-${pkg.version} ` +
            `dependencies=[${pkg.dependencies.join(", ") || "none"}]`
        );
    }
}


// ---------------------------------------------------------------------------
// Service supervision
// ---------------------------------------------------------------------------

class ServiceSupervisor extends EventEmitter {
    constructor() {
        super();
        this.services = new Map();
    }

    register(service) {
        if (this.services.has(service.name)) {
            throw new Error(`service already registered: ${service.name}`);
        }

        this.services.set(service.name, {
            ...service,
            state: "inactive",
            restartCount: 0,
        });
    }

    start(name) {
        const service = this.get(name);

        if (service.state === "active") return;

        service.state = "active";
        this.emit("started", service);
    }

    fail(name, reason) {
        const service = this.get(name);
        service.state = "failed";
        service.lastFailure = reason;

        this.emit("failed", service);

        if (service.restartPolicy === "on-failure") {
            service.restartCount += 1;
            this.start(name);
        }
    }

    stop(name) {
        const service = this.get(name);
        service.state = "inactive";
        this.emit("stopped", service);
    }

    get(name) {
        const service = this.services.get(name);

        if (!service) {
            throw new Error(`unknown service: ${name}`);
        }

        return service;
    }
}

async function serviceWorkflow() {
    console.log("\n=== Service Supervision ===");

    const supervisor = new ServiceSupervisor();

    supervisor.on("started", (service) => {
        console.log(
            `started: ${service.name}, restartCount=${service.restartCount}`
        );
    });

    supervisor.on("failed", (service) => {
        console.log(
            `failed: ${service.name}, reason=${service.lastFailure}`
        );
    });

    supervisor.on("stopped", (service) => {
        console.log(`stopped: ${service.name}`);
    });

    supervisor.register({
        name: "monitor-agent.service",
        command: "/usr/local/bin/monitor-agent",
        restartPolicy: "on-failure",
    });

    supervisor.start("monitor-agent.service");
    supervisor.fail("monitor-agent.service", "simulated connection failure");
    supervisor.stop("monitor-agent.service");
}


// ---------------------------------------------------------------------------
// Safe child-process execution
// ---------------------------------------------------------------------------

async function safeCommandExecution() {
    console.log("\n=== Safe Child-Process Execution ===");

    if (process.platform !== "linux") {
        console.log("Linux-specific command inspection is skipped on this host.");
        return;
    }

    /*
     * execFile passes arguments directly to the executable instead of asking
     * a shell to parse a constructed command string. This avoids shell
     * metacharacter interpretation and is safer when arguments are dynamic.
     */
    try {
        const { stdout } = await execFileAsync(
            "id",
            ["-u"],
            { encoding: "utf8" }
        );

        console.log(`Current effective UID reported by id: ${stdout.trim()}`);
    } catch (error) {
        console.log(`Unable to execute id safely: ${error.message}`);
    }
}


// ---------------------------------------------------------------------------
// /proc inspection
// ---------------------------------------------------------------------------

function readProcStatus(pid) {
    if (process.platform !== "linux") {
        throw new Error("/proc is a Linux-specific interface");
    }

    const statusPath = `/proc/${pid}/status`;
    const content = fs.readFileSync(statusPath, "utf8");
    const fields = new Map();

    for (const line of content.split("\n")) {
        const separator = line.indexOf(":");
        if (separator === -1) continue;

        fields.set(
            line.slice(0, separator),
            line.slice(separator + 1).trim()
        );
    }

    return fields;
}

function procWorkflow() {
    console.log("\n=== /proc Process Inspection ===");

    if (process.platform !== "linux") {
        console.log("This section requires Linux.");
        return;
    }

    try {
        const status = readProcStatus(process.pid);

        console.log(`PID   : ${process.pid}`);
        console.log(`Name  : ${status.get("Name") || "unknown"}`);
        console.log(`State : ${status.get("State") || "unknown"}`);
        console.log(`PPID  : ${status.get("PPid") || "unknown"}`);
        console.log(`UID   : ${status.get("Uid") || "unknown"}`);
        console.log(`Memory: ${status.get("VmRSS") || "unknown"}`);
    } catch (error) {
        /*
         * A process may disappear while being inspected. This is a normal
         * race in process enumeration and should be handled rather than
         * interpreted as a corrupt system.
         */
        console.log(`Could not read process state: ${error.message}`);
    }
}


// ---------------------------------------------------------------------------
// Host filesystem inspection
// ---------------------------------------------------------------------------

function filesystemWorkflow() {
    console.log("\n=== Host Filesystem Inspection ===");

    const targets = ["/", "/etc", "/tmp", "/proc", "/var", "/usr"];

    for (const target of targets) {
        try {
            const result = describeFilesystemEntry(target);

            console.log(
                `${result.path.padEnd(8)} ` +
                `${result.type.padEnd(15)} ` +
                `${result.permissions} ` +
                `${result.octal} ` +
                `uid=${result.uid} gid=${result.gid}`
            );
        } catch (error) {
            console.log(`${target}: unavailable (${error.message})`);
        }
    }
}


// ---------------------------------------------------------------------------
// Integrated deployment policy
// ---------------------------------------------------------------------------

function evaluateDeploymentPolicy() {
    console.log("\n=== Integrated Deployment Policy ===");

    const artifacts = [
        {
            path: "/srv/monitor/bin/monitor",
            owner: "deploy",
            group: "webops",
            mode: 0o750,
        },
        {
            path: "/srv/monitor/config",
            owner: "root",
            group: "webops",
            mode: 0o640,
        },
        {
            path: "/srv/monitor/log",
            owner: "monitor",
            group: "webops",
            mode: 0o2770,
        },
    ];

    for (const artifact of artifacts) {
        const worldWritable = Boolean(artifact.mode & 0o002);
        const ownerExecutable =
            Boolean(artifact.mode & 0o100) &&
            artifact.path.endsWith("/monitor");

        const problems = [];

        if (worldWritable) {
            problems.push("world-writable");
        }

        if (artifact.path.endsWith("/monitor") && !ownerExecutable) {
            problems.push("deployment executable lacks owner execute permission");
        }

        console.log(
            `${artifact.path}: ` +
            `${artifact.owner}:${artifact.group} ` +
            `${modeToOctal(artifact.mode)} ` +
            `${problems.length ? problems.join("; ") : "policy accepted"}`
        );
    }

    console.log(
        "\nThe policy connects filesystem ownership with the account used by " +
        "the service. A service can be correctly started yet still fail when " +
        "its runtime identity cannot read configuration or write its log path."
    );
}


// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
    console.log("Linux Fundamentals Laboratory");
    console.log("==============================");
    console.log(`Node.js ${process.version}`);
    console.log(`Platform: ${os.platform()} ${os.release()}`);
    console.log(`Working directory: ${path.resolve(".")}`);

    filesystemWorkflow();
    permissionWorkflow();
    processLifecycleWorkflow();
    packageWorkflow();
    procWorkflow();
    evaluateDeploymentPolicy();

    await serviceWorkflow();
    await safeCommandExecution();

    console.log("\nLaboratory completed without modifying system state.");
}

main().catch((error) => {
    console.error(`Fatal error: ${error.message}`);
    process.exitCode = 1;
});
