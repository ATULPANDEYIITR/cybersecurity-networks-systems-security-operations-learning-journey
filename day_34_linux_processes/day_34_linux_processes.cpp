#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

/*
 * Linux Process Governance Case Study
 *
 * Scenario:
 * A lightweight Linux service supervisor launches several worker processes.
 * The supervisor records PIDs, maintains parent/child relationships, checks
 * worker health, reacts to SIGCHLD, and terminates workers through a controlled
 * shutdown path.
 *
 * This is intentionally different from a simple syntax demonstration:
 * the program models the core responsibilities of a process supervisor.
 *
 * Build:
 *   g++ -std=c++17 -Wall -Wextra -pedantic process_governance.cpp -o process_governance
 *
 * Run:
 *   ./process_governance
 */

namespace fs = std::filesystem;

volatile sig_atomic_t child_exit_event = 0;
volatile sig_atomic_t shutdown_event = 0;

extern "C" void handle_sigchld(int) {
    child_exit_event = 1;
}

extern "C" void handle_sigterm(int) {
    shutdown_event = 1;
}

struct WorkerSpec {
    std::string name;
    int runtime_seconds;
    int exit_code;
};

struct WorkerRecord {
    std::string name;
    pid_t pid;
    pid_t parent_pid;
    int expected_exit_code;
    bool running;
    bool reaped;
    int wait_status;
};

std::string describe_wait_status(int status) {
    if (WIFEXITED(status)) {
        return "exited with code " + std::to_string(WEXITSTATUS(status));
    }

    if (WIFSIGNALED(status)) {
        return "terminated by signal " +
               std::to_string(WTERMSIG(status));
    }

    if (WIFSTOPPED(status)) {
        return "stopped by signal " +
               std::to_string(WSTOPSIG(status));
    }

    if (WIFCONTINUED(status)) {
        return "continued";
    }

    return "unknown wait status";
}

std::optional<std::string> read_proc_field(pid_t pid, const std::string& field) {
    const fs::path status_path =
        fs::path("/proc") / std::to_string(pid) / "status";

    std::ifstream input(status_path);
    if (!input) {
        return std::nullopt;
    }

    std::string line;

    while (std::getline(input, line)) {
        if (line.rfind(field + ":", 0) == 0) {
            return line.substr(field.size() + 1);
        }
    }

    return std::nullopt;
}

void print_process_metadata(pid_t pid) {
    std::cout << "PID " << pid << " metadata\n";

    const auto name = read_proc_field(pid, "Name");
    const auto state = read_proc_field(pid, "State");
    const auto ppid = read_proc_field(pid, "PPid");
    const auto threads = read_proc_field(pid, "Threads");

    std::cout << "  Name:    " << name.value_or("unavailable") << '\n';
    std::cout << "  State:   " << state.value_or("unavailable") << '\n';
    std::cout << "  PPid:    " << ppid.value_or("unavailable") << '\n';
    std::cout << "  Threads: " << threads.value_or("unavailable") << '\n';
}

void worker_main(const WorkerSpec& spec) {
    /*
     * The child inherits the parent's address space at fork(), but after fork
     * it has its own execution context and PID. _exit() avoids running parent
     * process cleanup handlers twice.
     */
    std::cout << "[worker " << spec.name << "] PID=" << getpid()
              << " PPID=" << getppid() << '\n';

    for (int second = 1; second <= spec.runtime_seconds; ++second) {
        std::cout << "[worker " << spec.name << "] tick "
                  << second << '\n';

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "[worker " << spec.name << "] exiting with code "
              << spec.exit_code << '\n';

    _exit(spec.exit_code);
}

pid_t launch_worker(const WorkerSpec& spec) {
    const pid_t pid = fork();

    if (pid < 0) {
        throw std::runtime_error(
            "fork() failed: " + std::string(std::strerror(errno))
        );
    }

    if (pid == 0) {
        worker_main(spec);
    }

    return pid;
}

void install_signal_handlers() {
    struct sigaction child_action {};
    child_action.sa_handler = handle_sigchld;
    sigemptyset(&child_action.sa_mask);
    child_action.sa_flags = SA_RESTART | SA_NOCLDSTOP;

    if (sigaction(SIGCHLD, &child_action, nullptr) == -1) {
        throw std::runtime_error("Could not install SIGCHLD handler.");
    }

    struct sigaction term_action {};
    term_action.sa_handler = handle_sigterm;
    sigemptyset(&term_action.sa_mask);
    term_action.sa_flags = SA_RESTART;

    if (sigaction(SIGTERM, &term_action, nullptr) == -1) {
        throw std::runtime_error("Could not install SIGTERM handler.");
    }

    if (sigaction(SIGINT, &term_action, nullptr) == -1) {
        throw std::runtime_error("Could not install SIGINT handler.");
    }
}

void reap_finished_workers(
    std::map<pid_t, WorkerRecord>& workers
) {
    while (true) {
        int status = 0;

        /*
         * WNOHANG makes waitpid() non-blocking. A supervisor must be able to
         * process other workers rather than becoming stuck waiting for one.
         */
        const pid_t pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            if (errno == ECHILD) {
                return;
            }

            if (errno == EINTR) {
                continue;
            }

            std::cerr << "waitpid() failed: "
                      << std::strerror(errno) << '\n';
            return;
        }

        auto it = workers.find(pid);

        if (it == workers.end()) {
            std::cerr << "Reaped unknown child PID " << pid << '\n';
            continue;
        }

        it->second.running = false;
        it->second.reaped = true;
        it->second.wait_status = status;

        std::cout << "[supervisor] Reaped worker "
                  << it->second.name
                  << " PID=" << pid
                  << ": " << describe_wait_status(status)
                  << '\n';
    }

    child_exit_event = 0;
}

bool all_workers_finished(
    const std::map<pid_t, WorkerRecord>& workers
) {
    return std::all_of(
        workers.begin(),
        workers.end(),
        [](const auto& pair) {
            return pair.second.reaped;
        }
    );
}

void terminate_workers(
    std::map<pid_t, WorkerRecord>& workers,
    int signal_number
) {
    for (auto& [pid, worker] : workers) {
        if (!worker.running) {
            continue;
        }

        /*
         * kill() sends a signal to the individual worker. A production
         * supervisor may instead place an application tree into a process
         * group and signal the group when all descendants must stop.
         */
        if (kill(pid, signal_number) == -1) {
            if (errno != ESRCH) {
                std::cerr << "kill(" << pid << ") failed: "
                          << std::strerror(errno) << '\n';
            }
        } else {
            std::cout << "[supervisor] Sent signal "
                      << signal_number
                      << " to PID " << pid << '\n';
        }
    }
}

void print_governance_report(
    const std::map<pid_t, WorkerRecord>& workers
) {
    std::cout << "\nProcess Governance Report\n";
    std::cout << "Supervisor PID: " << getpid() << '\n';

    for (const auto& [pid, worker] : workers) {
        std::cout
            << "  " << worker.name
            << " PID=" << worker.pid
            << " parent=" << worker.parent_pid
            << " expected_exit=" << worker.expected_exit_code
            << " running=" << std::boolalpha << worker.running
            << " reaped=" << worker.reaped;

        if (worker.reaped) {
            std::cout << " result=" << describe_wait_status(worker.wait_status);
        }

        std::cout << '\n';
    }
}

int main() {
    try {
        install_signal_handlers();

        std::cout << "Linux Process Governance Engine\n";
        std::cout << "Supervisor PID: " << getpid() << '\n';
        std::cout << "Supervisor PPID: " << getppid() << '\n';

        /*
         * The worker set represents a realistic service with separate
         * responsibilities. One worker intentionally returns a non-zero
         * status so that the supervisor can distinguish application failure
         * from signal termination.
         */
        const std::vector<WorkerSpec> specifications = {
            {"metrics", 2, 0},
            {"api-worker", 4, 0},
            {"audit-worker", 3, 17}
        };

        std::map<pid_t, WorkerRecord> workers;

        for (const auto& spec : specifications) {
            const pid_t pid = launch_worker(spec);

            workers.emplace(
                pid,
                WorkerRecord{
                    spec.name,
                    pid,
                    getpid(),
                    spec.exit_code,
                    true,
                    false,
                    0
                }
            );

            std::cout
                << "[supervisor] Started "
                << spec.name
                << " PID=" << pid
                << " PPID=" << getpid()
                << '\n';

            print_process_metadata(pid);
        }

        const auto start = std::chrono::steady_clock::now();
        const auto supervision_deadline =
            start + std::chrono::seconds(7);

        /*
         * This event loop is the central case-study mechanism. It does not
         * continuously call blocking waitpid(). Instead it periodically
         * handles child-exit events and shutdown requests.
         */
        while (!all_workers_finished(workers)) {
            if (shutdown_event) {
                std::cout
                    << "[supervisor] Shutdown requested; "
                    << "sending SIGTERM to active workers.\n";

                terminate_workers(workers, SIGTERM);
                shutdown_event = 0;
            }

            if (child_exit_event) {
                reap_finished_workers(workers);
                child_exit_event = 0;
            } else {
                /*
                 * Even without SIGCHLD delivery at this exact moment, a
                 * non-blocking wait protects against missed event timing and
                 * keeps the supervisor's state synchronized.
                 */
                reap_finished_workers(workers);
            }

            if (all_workers_finished(workers)) {
                break;
            }

            if (std::chrono::steady_clock::now() > supervision_deadline) {
                std::cout
                    << "[supervisor] Global deadline exceeded; "
                    << "forcing remaining workers to stop.\n";

                terminate_workers(workers, SIGTERM);

                std::this_thread::sleep_for(
                    std::chrono::milliseconds(300)
                );

                reap_finished_workers(workers);

                if (!all_workers_finished(workers)) {
                    std::cout
                        << "[supervisor] Some workers remain alive; "
                        << "using SIGKILL.\n";

                    terminate_workers(workers, SIGKILL);

                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(100)
                    );

                    reap_finished_workers(workers);
                }

                break;
            }

            std::this_thread::sleep_for(
                std::chrono::milliseconds(100)
            );
        }

        reap_finished_workers(workers);
        print_governance_report(workers);

        /*
         * A supervisor must not simply forget terminated children. Reaping
         * with waitpid() removes their kernel exit records and prevents
         * zombie accumulation.
         */
        for (auto& [pid, worker] : workers) {
            if (!worker.reaped) {
                int status = 0;

                while (waitpid(pid, &status, 0) == -1) {
                    if (errno == EINTR) {
                        continue;
                    }

                    break;
                }

                worker.running = false;
                worker.reaped = true;
                worker.wait_status = status;
            }
        }

        std::cout << "\nAll managed workers have been reaped.\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "Fatal supervisor error: "
                  << error.what() << '\n';
        return 1;
    }
}
