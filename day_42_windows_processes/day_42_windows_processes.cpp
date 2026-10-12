#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

/*
 * Repository-independent Windows process governance case study:
 *
 * Model a diagnostic agent that receives a process snapshot, reconstructs
 * parent-child relationships, associates Windows services with process IDs,
 * and decides which records are safe to report as a consistent hierarchy.
 *
 * This program uses simulated input so it compiles and runs without Windows
 * privileges or external libraries. The data structures can consume records
 * collected separately through Win32_Process, Toolhelp, or documented Windows
 * APIs. It never opens, suspends, or terminates a real process.
 */

struct ProcessRecord {
    std::uint32_t pid{};
    std::optional<std::uint32_t> parentPid;
    std::string name;
    std::uint32_t threadCount{};
};

struct ServiceRecord {
    std::string name;
    std::string state;
    std::uint32_t pid{};
};

struct Diagnostic {
    std::string severity;
    std::string message;
};

class ProcessSnapshot {
public:
    explicit ProcessSnapshot(std::vector<ProcessRecord> records) {
        for (auto& record : records) {
            if (record.pid == 0) {
                throw std::invalid_argument("PID zero is not a valid process identity");
            }
            if (record.name.empty()) {
                throw std::invalid_argument("Process name cannot be empty");
            }
            if (!records_.emplace(record.pid, std::move(record)).second) {
                throw std::invalid_argument("Duplicate process ID in snapshot");
            }
        }
        buildRelationships();
    }

    const std::map<std::uint32_t, ProcessRecord>& records() const {
        return records_;
    }

    const std::vector<std::uint32_t>& childrenOf(std::uint32_t pid) const {
        static const std::vector<std::uint32_t> empty;
        const auto found = children_.find(pid);
        return found == children_.end() ? empty : found->second;
    }

    std::vector<std::uint32_t> roots() const {
        std::vector<std::uint32_t> result;
        for (const auto& [pid, process] : records_) {
            if (!process.parentPid || records_.find(*process.parentPid) == records_.end()) {
                result.push_back(pid);
            }
        }
        return result;
    }

    std::vector<std::uint32_t> descendants(std::uint32_t rootPid) const {
        if (records_.find(rootPid) == records_.end()) {
            throw std::out_of_range("Requested PID is absent from the snapshot");
        }

        // An indexed queue gives O(V + E) traversal for the process subgraph.
        std::vector<std::uint32_t> queue;
        std::vector<std::uint32_t> result;
        std::unordered_set<std::uint32_t> visited{rootPid};
        const auto& initialChildren = childrenOf(rootPid);
        queue.insert(queue.end(), initialChildren.begin(), initialChildren.end());

        for (std::size_t cursor = 0; cursor < queue.size(); ++cursor) {
            const std::uint32_t current = queue[cursor];
            if (!visited.insert(current).second) {
                continue;
            }
            result.push_back(current);
            const auto& children = childrenOf(current);
            queue.insert(queue.end(), children.begin(), children.end());
        }
        return result;
    }

    std::vector<Diagnostic> validate() const {
        std::vector<Diagnostic> diagnostics;

        for (const auto& [pid, process] : records_) {
            if (process.parentPid && *process.parentPid == pid) {
                diagnostics.push_back({
                    "ERROR",
                    "PID " + std::to_string(pid) + " is its own parent"
                });
            } else if (process.parentPid &&
                       records_.find(*process.parentPid) == records_.end()) {
                diagnostics.push_back({
                    "INFO",
                    "Parent PID " + std::to_string(*process.parentPid) +
                    " for PID " + std::to_string(pid) +
                    " is absent from the snapshot"
                });
            }
        }

        // Parent links form a directed graph. Detect cycles explicitly instead
        // of assuming every record eventually reaches a root.
        enum class Mark { Unseen, Visiting, Complete };
        std::unordered_map<std::uint32_t, Mark> marks;

        for (const auto& [startPid, unused] : records_) {
            (void)unused;
            if (marks[startPid] == Mark::Complete) {
                continue;
            }

            std::vector<std::uint32_t> path;
            std::uint32_t current = startPid;

            while (records_.find(current) != records_.end()) {
                const Mark mark = marks[current];

                if (mark == Mark::Complete) {
                    break;
                }
                if (mark == Mark::Visiting) {
                    diagnostics.push_back({
                        "ERROR",
                        "Parent cycle detected while following PID " +
                        std::to_string(current)
                    });
                    break;
                }

                marks[current] = Mark::Visiting;
                path.push_back(current);

                const auto& process = records_.at(current);
                if (!process.parentPid ||
                    records_.find(*process.parentPid) == records_.end()) {
                    break;
                }
                current = *process.parentPid;
            }

            for (const auto pid : path) {
                marks[pid] = Mark::Complete;
            }
        }

        return diagnostics;
    }

    std::uint64_t totalThreads() const {
        std::uint64_t total = 0;
        for (const auto& [pid, process] : records_) {
            (void)pid;
            total += process.threadCount;
        }
        return total;
    }

private:
    std::map<std::uint32_t, ProcessRecord> records_;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> children_;

    void buildRelationships() {
        for (const auto& [pid, process] : records_) {
            if (process.parentPid && records_.find(*process.parentPid) != records_.end()) {
                children_[*process.parentPid].push_back(pid);
            }
        }

        for (auto& [parentPid, childPids] : children_) {
            (void)parentPid;
            std::sort(childPids.begin(), childPids.end());
        }
    }
};

class ServiceCorrelator {
public:
    explicit ServiceCorrelator(const ProcessSnapshot& snapshot) : snapshot_(snapshot) {}

    void report(const std::vector<ServiceRecord>& services) const {
        std::cout << "\nService-to-process correlation\n";
        for (const auto& service : services) {
            const auto process = snapshot_.records().find(service.pid);
            std::cout << "Service: " << service.name
                      << " | state: " << service.state
                      << " | PID: " << service.pid;

            if (service.pid == 0) {
                std::cout << " | no process currently assigned";
            } else if (process == snapshot_.records().end()) {
                std::cout << " | PID absent from snapshot";
            } else {
                std::cout << " | process: " << process->second.name;
            }
            std::cout << '\n';
        }
    }

private:
    const ProcessSnapshot& snapshot_;
};

void printTree(const ProcessSnapshot& snapshot) {
    std::cout << "\nProcess hierarchy\n";
    std::unordered_set<std::uint32_t> visited;

    for (const auto rootPid : snapshot.roots()) {
        struct Frame {
            std::uint32_t pid;
            std::string prefix;
            bool last;
        };

        std::vector<Frame> stack{{rootPid, "", true}};

        while (!stack.empty()) {
            Frame frame = std::move(stack.back());
            stack.pop_back();

            if (!visited.insert(frame.pid).second) {
                std::cout << frame.prefix << "[repeated PID "
                          << frame.pid << "]\n";
                continue;
            }

            const auto& process = snapshot.records().at(frame.pid);
            std::cout << frame.prefix
                      << (frame.last ? "`-- " : "|-- ")
                      << process.name << " (PID " << process.pid
                      << ", threads=" << process.threadCount << ")\n";

            const auto& children = snapshot.childrenOf(frame.pid);
            const std::string nextPrefix =
                frame.prefix + (frame.last ? "    " : "|   ");

            for (std::size_t i = children.size(); i > 0; --i) {
                stack.push_back({
                    children[i - 1],
                    nextPrefix,
                    i == children.size()
                });
            }
        }
    }

    // Cyclic components have no roots and must be surfaced separately.
    for (const auto& [pid, process] : snapshot.records()) {
        if (visited.find(pid) == visited.end()) {
            std::cout << "[unreachable component] "
                      << process.name << " (PID " << pid << ")\n";
            visited.insert(pid);
        }
    }
}

int main() {
    try {
        std::vector<ProcessRecord> records{
            {4, std::nullopt, "System", 180},
            {620, 4, "services.exe", 12},
            {840, 620, "svchost.exe", 28},
            {960, 620, "svchost.exe", 34},
            {1200, 620, "explorer.exe", 42},
            {1300, 1200, "notepad.exe", 8},
            {1450, 1200, "powershell.exe", 14},
            {1500, 1450, "python.exe", 6},
            {1700, 1200, "chrome.exe", 31},
            {1710, 1700, "chrome.exe", 16},
            {1720, 1700, "chrome.exe", 22},
            // The parent is absent. This may reflect a partial snapshot,
            // process exit, or PID reuse rather than a security incident.
            {1900, 9999, "diagnostic-worker.exe", 5}
        };

        ProcessSnapshot snapshot(std::move(records));

        std::cout << "Windows process diagnostic case study\n";
        std::cout << "Processes: " << snapshot.records().size() << '\n';
        std::cout << "Reported threads: " << snapshot.totalThreads() << '\n';
        printTree(snapshot);

        std::cout << "\nSnapshot diagnostics\n";
        const auto diagnostics = snapshot.validate();
        if (diagnostics.empty()) {
            std::cout << "No structural anomalies detected.\n";
        }
        for (const auto& diagnostic : diagnostics) {
            std::cout << '[' << diagnostic.severity << "] "
                      << diagnostic.message << '\n';
        }

        std::cout << "\nDescendants of explorer.exe (PID 1200)\n";
        for (const auto pid : snapshot.descendants(1200)) {
            const auto& process = snapshot.records().at(pid);
            std::cout << "PID " << pid << " | " << process.name << '\n';
        }

        const std::vector<ServiceRecord> services{
            {"ExampleTelemetry", "Running", 840},
            {"ExampleUpdater", "Stopped", 0},
            {"ExampleAgent", "Running", 9999}
        };

        ServiceCorrelator correlator(snapshot);
        correlator.report(services);

        // A diagnostic report is not proof of process ancestry. Production
        // collectors should use creation times and stable handles where
        // available, since PIDs can be reused between observations.
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Diagnostic failure: " << error.what() << '\n';
        return 1;
    }
}
