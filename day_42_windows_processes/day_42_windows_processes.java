import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * Enterprise-oriented Windows process inventory and service diagnostics.
 *
 * Compile and run:
 *   javac WindowsProcessGovernance.java
 *   java WindowsProcessGovernance
 *
 * This program uses sample records and the Java standard library. It models
 * diagnostic behavior without requiring elevated Windows permissions and
 * never starts, stops, or terminates operating-system processes.
 */
public class WindowsProcessGovernance {

    enum ProcessState {
        OBSERVED,
        EXITED,
        ACCESS_DENIED,
        METADATA_UNAVAILABLE
    }

    enum ServiceState {
        RUNNING,
        STOPPED,
        PAUSED,
        START_PENDING,
        STOP_PENDING,
        UNKNOWN
    }

    enum Severity {
        INFO,
        WARNING,
        ERROR
    }

    record ProcessIdentity(int pid, Instant observedAt) {
        ProcessIdentity {
            if (pid <= 0) {
                throw new IllegalArgumentException("PID must be positive");
            }
            Objects.requireNonNull(observedAt, "observedAt");
        }
    }

    record ProcessRecord(
            ProcessIdentity identity,
            Integer parentPid,
            String imageName,
            int threadCount,
            ProcessState state,
            Optional<String> executablePath) {

        ProcessRecord {
            Objects.requireNonNull(identity, "identity");
            Objects.requireNonNull(imageName, "imageName");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(executablePath, "executablePath");

            if (imageName.isBlank()) {
                throw new IllegalArgumentException("Image name cannot be blank");
            }
            if (parentPid != null && parentPid <= 0) {
                throw new IllegalArgumentException("Parent PID must be positive");
            }
            if (threadCount < 0) {
                throw new IllegalArgumentException("Thread count cannot be negative");
            }
            if (parentPid != null && parentPid == identity.pid()) {
                throw new IllegalArgumentException("A process cannot parent itself");
            }
        }

        int pid() {
            return identity.pid();
        }
    }

    record ServiceRecord(
            String name,
            String displayName,
            ServiceState state,
            String startMode,
            int processId) {

        ServiceRecord {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(displayName, "displayName");
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(startMode, "startMode");
            if (name.isBlank()) {
                throw new IllegalArgumentException("Service name cannot be blank");
            }
            if (processId < 0) {
                throw new IllegalArgumentException("Service PID cannot be negative");
            }
        }
    }

    record Diagnostic(Severity severity, String code, String message) {}

    static final class ProcessInventory {
        private final Map<Integer, ProcessRecord> processes;
        private final Map<Integer, List<Integer>> children;

        ProcessInventory(List<ProcessRecord> records) {
            Map<Integer, ProcessRecord> processMap = new TreeMap<>();

            for (ProcessRecord record : records) {
                if (processMap.putIfAbsent(record.pid(), record) != null) {
                    throw new IllegalArgumentException(
                            "Duplicate PID in snapshot: " + record.pid());
                }
            }

            Map<Integer, List<Integer>> childMap = new HashMap<>();
            for (ProcessRecord record : processMap.values()) {
                if (record.parentPid() != null &&
                        processMap.containsKey(record.parentPid())) {
                    childMap.computeIfAbsent(record.parentPid(),
                            ignored -> new ArrayList<>()).add(record.pid());
                }
            }

            childMap.values().forEach(list -> list.sort(Integer::compareTo));
            this.processes = Map.copyOf(processMap);
            this.children = Map.copyOf(childMap);
        }

        Map<Integer, ProcessRecord> processes() {
            return processes;
        }

        List<Integer> roots() {
            return processes.values().stream()
                    .filter(process -> process.parentPid() == null ||
                            !processes.containsKey(process.parentPid()))
                    .map(ProcessRecord::pid)
                    .sorted()
                    .toList();
        }

        List<ProcessRecord> descendants(int pid) {
            if (!processes.containsKey(pid)) {
                throw new IllegalArgumentException("PID is absent: " + pid);
            }

            List<ProcessRecord> result = new ArrayList<>();
            Deque<Integer> queue = new ArrayDeque<>(
                    children.getOrDefault(pid, List.of()));
            Set<Integer> visited = new HashSet<>();
            visited.add(pid);

            while (!queue.isEmpty()) {
                int current = queue.removeFirst();
                if (!visited.add(current)) {
                    continue;
                }

                ProcessRecord record = processes.get(current);
                if (record == null) {
                    continue;
                }
                result.add(record);
                queue.addAll(children.getOrDefault(current, List.of()));
            }
            return List.copyOf(result);
        }

        List<Diagnostic> diagnose() {
            List<Diagnostic> result = new ArrayList<>();

            for (ProcessRecord process : processes.values()) {
                if (process.parentPid() != null &&
                        !processes.containsKey(process.parentPid())) {
                    result.add(new Diagnostic(
                            Severity.INFO,
                            "PARENT_NOT_OBSERVED",
                            "PID " + process.pid() + " refers to parent PID " +
                                    process.parentPid() + " absent from this snapshot"));
                }

                if (process.state() == ProcessState.ACCESS_DENIED) {
                    result.add(new Diagnostic(
                            Severity.WARNING,
                            "ACCESS_DENIED",
                            "Some metadata for PID " + process.pid() + " is unavailable"));
                }
            }

            // Parent chains are normally shallow. An iterative color-marking
            // pass avoids recursion limits and identifies malformed cycles.
            enum Mark { VISITING, COMPLETE }
            Map<Integer, Mark> marks = new HashMap<>();

            for (int start : processes.keySet()) {
                if (marks.get(start) == Mark.COMPLETE) {
                    continue;
                }

                List<Integer> path = new ArrayList<>();
                int current = start;

                while (processes.containsKey(current)) {
                    Mark mark = marks.get(current);
                    if (mark == Mark.COMPLETE) {
                        break;
                    }
                    if (mark == Mark.VISITING) {
                        result.add(new Diagnostic(
                                Severity.ERROR,
                                "PARENT_CYCLE",
                                "Cycle detected at PID " + current));
                        break;
                    }

                    marks.put(current, Mark.VISITING);
                    path.add(current);

                    Integer parent = processes.get(current).parentPid();
                    if (parent == null || !processes.containsKey(parent)) {
                        break;
                    }
                    current = parent;
                }

                path.forEach(pid -> marks.put(pid, Mark.COMPLETE));
            }

            return List.copyOf(result);
        }

        long totalReportedThreads() {
            return processes.values().stream()
                    .mapToLong(ProcessRecord::threadCount)
                    .sum();
        }
    }

    static final class ServiceCorrelationService {
        private final ProcessInventory inventory;

        ServiceCorrelationService(ProcessInventory inventory) {
            this.inventory = Objects.requireNonNull(inventory);
        }

        void report(List<ServiceRecord> services) {
            System.out.println("\nService correlation");

            for (ServiceRecord service : services) {
                if (service.processId() == 0) {
                    System.out.printf(
                            "%s: %s, no process currently assigned%n",
                            service.name(), service.state());
                    continue;
                }

                ProcessRecord process = inventory.processes().get(service.processId());
                if (process == null) {
                    System.out.printf(
                            "%s: %s, PID %d absent from snapshot%n",
                            service.name(), service.state(), service.processId());
                } else {
                    System.out.printf(
                            "%s: %s, PID %d, image=%s%n",
                            service.name(), service.state(), process.pid(),
                            process.imageName());
                }
            }
        }
    }

    static final class DiagnosticReport {
        private final ProcessInventory inventory;

        DiagnosticReport(ProcessInventory inventory) {
            this.inventory = inventory;
        }

        void print() {
            System.out.println("Windows process inventory");
            System.out.println("Observed processes: " + inventory.processes().size());
            System.out.println("Reported threads: " + inventory.totalReportedThreads());
            System.out.println("Roots in snapshot: " + inventory.roots().size());

            System.out.println("\nProcesses with the highest thread counts");
            inventory.processes().values().stream()
                    .sorted(Comparator.comparingInt(ProcessRecord::threadCount)
                            .reversed())
                    .limit(8)
                    .forEach(process -> System.out.printf(
                            "PID %d | %-25s | %d threads%n",
                            process.pid(), process.imageName(), process.threadCount()));

            System.out.println("\nProcess hierarchy");
            Set<Integer> visited = new HashSet<>();

            for (int rootPid : inventory.roots()) {
                record Frame(int pid, String prefix, boolean last) {}
                Deque<Frame> stack = new ArrayDeque<>();
                stack.push(new Frame(rootPid, "", true));

                while (!stack.isEmpty()) {
                    Frame frame = stack.pop();
                    if (!visited.add(frame.pid())) {
                        System.out.println(frame.prefix() + "[repeated PID]");
                        continue;
                    }

                    ProcessRecord process = inventory.processes().get(frame.pid());
                    System.out.printf("%s%s%s (PID %d)%n",
                            frame.prefix(),
                            frame.last() ? "└── " : "├── ",
                            process.imageName(),
                            process.pid());

                    List<Integer> childPids =
                            new ArrayList<>(inventory.children.getOrDefault(
                                    frame.pid(), List.of()));
                    String childPrefix =
                            frame.prefix() + (frame.last() ? "    " : "│   ");

                    for (int index = childPids.size() - 1; index >= 0; index--) {
                        stack.push(new Frame(
                                childPids.get(index),
                                childPrefix,
                                index == childPids.size() - 1));
                    }
                }
            }

            System.out.println("\nDiagnostics");
            List<Diagnostic> diagnostics = inventory.diagnose();
            if (diagnostics.isEmpty()) {
                System.out.println("No structural anomalies detected.");
            }

            for (Diagnostic diagnostic : diagnostics) {
                System.out.printf("[%s] %s: %s%n",
                        diagnostic.severity(),
                        diagnostic.code(),
                        diagnostic.message());
            }
        }
    }

    private static List<ProcessRecord> sampleProcesses() {
        Instant observedAt = Instant.now();

        return List.of(
                new ProcessRecord(
                        new ProcessIdentity(4, observedAt), null, "System", 180,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(620, observedAt), 4, "services.exe", 12,
                        ProcessState.OBSERVED, Optional.of("C:\\Windows\\System32\\services.exe")),
                new ProcessRecord(
                        new ProcessIdentity(840, observedAt), 620, "svchost.exe", 28,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(960, observedAt), 620, "svchost.exe", 34,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(1200, observedAt), 620, "explorer.exe", 42,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(1300, observedAt), 1200, "notepad.exe", 8,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(1450, observedAt), 1200, "powershell.exe", 14,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(1500, observedAt), 1450, "python.exe", 6,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(1700, observedAt), 1200, "chrome.exe", 31,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(1710, observedAt), 1700, "chrome.exe", 16,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(1720, observedAt), 1700, "chrome.exe", 22,
                        ProcessState.OBSERVED, Optional.empty()),
                new ProcessRecord(
                        new ProcessIdentity(1900, observedAt), 9999,
                        "diagnostic-worker.exe", 5,
                        ProcessState.METADATA_UNAVAILABLE, Optional.empty())
        );
    }

    public static void main(String[] args) {
        try {
            ProcessInventory inventory = new ProcessInventory(sampleProcesses());
            new DiagnosticReport(inventory).print();

            List<ServiceRecord> services = List.of(
                    new ServiceRecord(
                            "ExampleTelemetry", "Example Telemetry",
                            ServiceState.RUNNING, "Auto", 840),
                    new ServiceRecord(
                            "ExampleUpdater", "Example Updater",
                            ServiceState.STOPPED, "Manual", 0),
                    new ServiceRecord(
                            "ExampleAgent", "Example Agent",
                            ServiceState.RUNNING, "Auto", 9999)
            );

            new ServiceCorrelationService(inventory).report(services);

            System.out.println("\nDescendants of PID 1200");
            inventory.descendants(1200).forEach(process ->
                    System.out.printf("PID %d: %s%n",
                            process.pid(), process.imageName()));

        } catch (IllegalArgumentException exception) {
            System.err.println("Invalid inventory: " + exception.getMessage());
            System.exitCode = 1;
        }
    }
}
