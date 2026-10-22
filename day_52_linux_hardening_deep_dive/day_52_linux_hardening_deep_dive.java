import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class LinuxHardeningAudit {

    enum Status {
        PASS, REVIEW, FAIL, UNKNOWN
    }

    enum Severity {
        INFO, MEDIUM, HIGH
    }

    record Finding(
            String category,
            String control,
            Status status,
            Severity severity,
            String evidence,
            String recommendation
    ) {}

    interface Control {
        Finding evaluate();
    }

    record KernelControl(
            String name,
            Path path,
            String expected
    ) implements Control {

        @Override
        public Finding evaluate() {
            try {
                String actual = Files.readString(path).trim();

                if (expected.equals(actual)) {
                    return new Finding(
                            "Kernel controls",
                            name,
                            Status.PASS,
                            Severity.INFO,
                            "Value " + actual,
                            "No immediate issue identified."
                    );
                }

                return new Finding(
                        "Kernel controls",
                        name,
                        Status.FAIL,
                        Severity.HIGH,
                        "Value " + actual + "; expected " + expected,
                        "Evaluate the setting using the distribution's supported persistent configuration."
                );
            } catch (IOException | SecurityException exception) {
                return new Finding(
                        "Kernel controls",
                        name,
                        Status.UNKNOWN,
                        Severity.MEDIUM,
                        exception.getMessage(),
                        "Inspect the kernel control with appropriate permissions."
                );
            }
        }
    }

    static final class RepositoryPolicy {
        private final boolean rootLoginDisabled;
        private final boolean passwordAuthenticationDisabled;
        private final boolean emptyPasswordsDisabled;
        private final boolean x11ForwardingDisabled;

        RepositoryPolicy(
                boolean rootLoginDisabled,
                boolean passwordAuthenticationDisabled,
                boolean emptyPasswordsDisabled,
                boolean x11ForwardingDisabled
        ) {
            this.rootLoginDisabled = rootLoginDisabled;
            this.passwordAuthenticationDisabled = passwordAuthenticationDisabled;
            this.emptyPasswordsDisabled = emptyPasswordsDisabled;
            this.x11ForwardingDisabled = x11ForwardingDisabled;
        }

        boolean secureBaselineSatisfied() {
            return rootLoginDisabled
                    && passwordAuthenticationDisabled
                    && emptyPasswordsDisabled
                    && x11ForwardingDisabled;
        }
    }

    static final class LinuxGovernanceService {
        private final List<Control> controls = new ArrayList<>();

        LinuxGovernanceService() {
            controls.add(new KernelControl(
                    "kernel.randomize_va_space",
                    Path.of("/proc/sys/kernel/randomize_va_space"),
                    "2"
            ));

            controls.add(new KernelControl(
                    "fs.protected_hardlinks",
                    Path.of("/proc/sys/fs/protected_hardlinks"),
                    "1"
            ));

            controls.add(new KernelControl(
                    "fs.protected_symlinks",
                    Path.of("/proc/sys/fs/protected_symlinks"),
                    "1"
            ));
        }

        List<Finding> evaluate() {
            List<Finding> findings = new ArrayList<>();

            findings.add(auditSsh());
            findings.add(auditSudo());
            findings.add(auditFile("/etc/passwd", 0644, false));
            findings.add(auditFile("/etc/shadow", 0640, true));
            findings.add(auditFile("/etc/sudoers", 0440, true));

            for (Control control : controls) {
                findings.add(control.evaluate());
            }

            findings.add(auditKernelAuditInterface());
            return findings;
        }

        private Finding auditSsh() {
            Path path = Path.of("/etc/ssh/sshd_config");

            try {
                String content = Files.readString(path);
                Map<String, String> configuration = parseConfiguration(content);

                String rootLogin = configuration.get("permitrootlogin");
                String passwordAuthentication =
                        configuration.get("passwordauthentication");
                String emptyPasswords =
                        configuration.get("permitemptypasswords");
                String x11 = configuration.get("x11forwarding");

                boolean secure =
                        ("no".equalsIgnoreCase(rootLogin)
                                || "prohibit-password".equalsIgnoreCase(rootLogin))
                        && "no".equalsIgnoreCase(passwordAuthentication)
                        && "no".equalsIgnoreCase(emptyPasswords)
                        && "no".equalsIgnoreCase(x11);

                if (secure) {
                    return new Finding(
                            "SSH",
                            "authentication baseline",
                            Status.PASS,
                            Severity.INFO,
                            "Root login, password authentication, empty passwords, and X11 forwarding are disabled.",
                            "Keep configuration synchronized with the organization's SSH access policy."
                    );
                }

                return new Finding(
                        "SSH",
                        "authentication baseline",
                        Status.REVIEW,
                        Severity.MEDIUM,
                        "One or more hardening directives are absent or permit a weaker configuration.",
                        "Review PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, and X11Forwarding."
                );
            } catch (IOException | SecurityException exception) {
                return new Finding(
                        "SSH",
                        "sshd_config",
                        Status.UNKNOWN,
                        Severity.MEDIUM,
                        exception.getMessage(),
                        "Inspect SSH configuration with appropriate permissions."
                );
            }
        }

        private Finding auditSudo() {
            Path path = Path.of("/etc/sudoers");

            try {
                String content = Files.readString(path);

                if (content.matches("(?s).*\\bNOPASSWD\\s*:.*")) {
                    return new Finding(
                            "sudo",
                            "passwordless elevation",
                            Status.REVIEW,
                            Severity.MEDIUM,
                            "At least one NOPASSWD rule is present in /etc/sudoers.",
                            "Confirm that every passwordless command is explicitly justified and narrowly scoped."
                    );
                }

                return new Finding(
                        "sudo",
                        "passwordless elevation",
                        Status.PASS,
                        Severity.INFO,
                        "No NOPASSWD rule found in /etc/sudoers.",
                        "Review included sudoers files for the complete policy."
                );
            } catch (IOException | SecurityException exception) {
                return new Finding(
                        "sudo",
                        "sudoers readability",
                        Status.UNKNOWN,
                        Severity.MEDIUM,
                        exception.getMessage(),
                        "Inspect sudo policy with appropriate permissions."
                );
            }
        }

        private Finding auditFile(
                String filename,
                int maximum,
                boolean sensitive
        ) {
            Path path = Path.of(filename);

            try {
                PosixFileAttributes attributes =
                        Files.readAttributes(path, PosixFileAttributes.class);

                int mode = toMode(attributes.permissions());
                int worldBits = mode & 7;

                if (sensitive && worldBits != 0) {
                    return new Finding(
                            "Filesystem permissions",
                            filename,
                            Status.FAIL,
                            Severity.HIGH,
                            String.format("Mode %04o grants world permissions.", mode),
                            "Remove unnecessary world permissions and verify ownership."
                    );
                }

                if ((mode & ~maximum) != 0) {
                    return new Finding(
                            "Filesystem permissions",
                            filename,
                            Status.REVIEW,
                            Severity.MEDIUM,
                            String.format(
                                    "Mode %04o exceeds baseline %04o.",
                                    mode,
                                    maximum
                            ),
                            "Confirm that additional permissions are intentional."
                    );
                }

                return new Finding(
                        "Filesystem permissions",
                        filename,
                        Status.PASS,
                        Severity.INFO,
                        String.format("Mode %04o.", mode),
                        "No excessive permissions detected against this baseline."
                );
            } catch (IOException | SecurityException exception) {
                return new Finding(
                        "Filesystem permissions",
                        filename,
                        Status.UNKNOWN,
                        Severity.MEDIUM,
                        exception.getMessage(),
                        "Inspect permissions and ownership manually."
                );
            }
        }

        private Finding auditKernelAuditInterface() {
            Path path = Path.of("/proc/sys/kernel/audit_enabled");

            try {
                String value = Files.readString(path).trim();

                if ("1".equals(value)) {
                    return new Finding(
                            "Auditing",
                            "kernel audit interface",
                            Status.PASS,
                            Severity.INFO,
                            "audit_enabled=1",
                            "Verify that persistent audit rules capture required security events."
                    );
                }

                return new Finding(
                        "Auditing",
                        "kernel audit interface",
                        Status.REVIEW,
                        Severity.HIGH,
                        "audit_enabled=" + value,
                        "Verify the active auditing architecture and persistent configuration."
                );
            } catch (IOException | SecurityException exception) {
                return new Finding(
                        "Auditing",
                        "kernel audit interface",
                        Status.UNKNOWN,
                        Severity.MEDIUM,
                        exception.getMessage(),
                        "Inspect the audit subsystem with administrative permissions."
                );
            }
        }

        private static Map<String, String> parseConfiguration(String content) {
            Map<String, String> result = new HashMap<>();

            for (String rawLine : content.split("\\R")) {
                String line = rawLine.trim();

                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                String[] parts = line.split("\\s+", 2);

                if (parts.length == 2) {
                    result.put(parts[0].toLowerCase(), parts[1].trim());
                }
            }

            return result;
        }

        private static int toMode(Set<PosixFilePermission> permissions) {
            int mode = 0;

            if (permissions.contains(PosixFilePermission.OWNER_READ)) mode |= 0400;
            if (permissions.contains(PosixFilePermission.OWNER_WRITE)) mode |= 0200;
            if (permissions.contains(PosixFilePermission.OWNER_EXECUTE)) mode |= 0100;

            if (permissions.contains(PosixFilePermission.GROUP_READ)) mode |= 0040;
            if (permissions.contains(PosixFilePermission.GROUP_WRITE)) mode |= 0020;
            if (permissions.contains(PosixFilePermission.GROUP_EXECUTE)) mode |= 0010;

            if (permissions.contains(PosixFilePermission.OTHERS_READ)) mode |= 0004;
            if (permissions.contains(PosixFilePermission.OTHERS_WRITE)) mode |= 0002;
            if (permissions.contains(PosixFilePermission.OTHERS_EXECUTE)) mode |= 0001;

            return mode;
        }
    }

    private static void printReport(List<Finding> findings) {
        Map<Status, Long> counts = new HashMap<>();

        for (Finding finding : findings) {
            counts.merge(finding.status(), 1L, Long::sum);

            System.out.printf(
                    "[%-7s] %-24s %s%n",
                    finding.status(),
                    finding.category(),
                    finding.control()
            );
            System.out.println("  Severity: " + finding.severity());
            System.out.println("  Evidence: " + finding.evidence());
            System.out.println("  Action:   " + finding.recommendation());
            System.out.println();
        }

        System.out.println("Generated: " + Instant.now());
        System.out.println("Result counts: " + counts);
    }

    public static void main(String[] args) {
        if (!System.getProperty("os.name").toLowerCase().contains("linux")) {
            System.err.println("This program requires Linux.");
            System.exit(2);
        }

        LinuxGovernanceService service = new LinuxGovernanceService();
        List<Finding> findings = service.evaluate();

        printReport(findings);

        boolean failure = findings.stream()
                .anyMatch(finding -> finding.status() == Status.FAIL);

        if (failure) {
            System.exit(1);
        }
    }
}
