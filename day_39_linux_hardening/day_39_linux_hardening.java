import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Enterprise Linux hardening assessment and change-governance model.
 *
 * Compile:
 *   javac LinuxHardening.java
 *
 * Run:
 *   java LinuxHardening
 *
 * This program evaluates supplied inventory records. It does not modify
 * the operating system or execute privileged commands.
 */
public class LinuxHardening {
    enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW, INFO
    }

    enum ChangeStatus {
        PROPOSED, APPROVED, SCHEDULED, EXECUTING, VERIFIED, FAILED, ROLLED_BACK
    }

    enum ControlFamily {
        ACCOUNT_SECURITY, SSH_HARDENING, FIREWALLING, PATCHING, AUDITING
    }

    record Finding(
        String controlId,
        ControlFamily family,
        Severity severity,
        String title,
        String evidence,
        String remediation
    ) {
        Finding {
            Objects.requireNonNull(controlId);
            Objects.requireNonNull(family);
            Objects.requireNonNull(severity);
            Objects.requireNonNull(title);
            Objects.requireNonNull(evidence);
            Objects.requireNonNull(remediation);
        }
    }

    record Account(
        String username,
        int uid,
        boolean passwordLocked,
        boolean interactive,
        boolean sudo,
        boolean serviceAccount,
        String shell,
        Set<String> groups
    ) {
        Account {
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException("Username cannot be blank.");
            }
            if (uid < 0) {
                throw new IllegalArgumentException("UID cannot be negative.");
            }
            Objects.requireNonNull(shell);
            groups = Set.copyOf(groups);
        }
    }

    record SshPolicy(
        boolean rootLoginAllowed,
        boolean passwordAuthentication,
        boolean publicKeyAuthentication,
        boolean tcpForwarding,
        int maxAuthTries,
        Set<String> allowedUsers
    ) {
        SshPolicy {
            if (maxAuthTries < 1) {
                throw new IllegalArgumentException("MaxAuthTries must be positive.");
            }
            allowedUsers = Set.copyOf(allowedUsers);
        }
    }

    record FirewallRule(
        String direction,
        String action,
        String protocol,
        Integer port,
        String source
    ) {
        FirewallRule {
            Objects.requireNonNull(direction);
            Objects.requireNonNull(action);
            Objects.requireNonNull(protocol);
            Objects.requireNonNull(source);

            if (port != null && (port < 1 || port > 65535)) {
                throw new IllegalArgumentException("Port must be from 1 through 65535.");
            }
        }
    }

    record FirewallPolicy(
        String inboundDefault,
        String outboundDefault,
        String forwardDefault,
        List<FirewallRule> rules
    ) {
        FirewallPolicy {
            Objects.requireNonNull(inboundDefault);
            Objects.requireNonNull(outboundDefault);
            Objects.requireNonNull(forwardDefault);
            rules = List.copyOf(rules);
        }
    }

    record PatchInventory(
        int criticalPending,
        int securityPending,
        int daysSinceSuccessfulUpdate,
        boolean rebootRequired,
        boolean unattendedUpdatesEnabled
    ) {
        PatchInventory {
            if (criticalPending < 0 || securityPending < 0 ||
                daysSinceSuccessfulUpdate < 0) {
                throw new IllegalArgumentException("Patch inventory values cannot be negative.");
            }
        }
    }

    record AuditInventory(
        boolean auditdEnabled,
        boolean persistentRules,
        boolean authenticationLogs,
        boolean timeSynchronization,
        boolean integrityMonitoring,
        int retentionDays
    ) {
        AuditInventory {
            if (retentionDays < 0) {
                throw new IllegalArgumentException("Retention cannot be negative.");
            }
        }
    }

    record Server(
        String hostname,
        List<Account> accounts,
        SshPolicy ssh,
        FirewallPolicy firewall,
        PatchInventory patches,
        AuditInventory audit
    ) {
        Server {
            if (hostname == null || hostname.isBlank()) {
                throw new IllegalArgumentException("Hostname is required.");
            }
            accounts = List.copyOf(accounts);
            Objects.requireNonNull(ssh);
            Objects.requireNonNull(firewall);
            Objects.requireNonNull(patches);
            Objects.requireNonNull(audit);
        }
    }

    static final Pattern USERNAME_PATTERN =
        Pattern.compile("[a-z_][a-z0-9_-]{0,31}\\$?");

    static final class AccountPolicy {
        List<Finding> evaluate(List<Account> accounts) {
            List<Finding> findings = new ArrayList<>();
            Set<String> names = new HashSet<>();
            Map<Integer, String> uidOwners = new java.util.HashMap<>();

            for (Account account : accounts) {
                if (!USERNAME_PATTERN.matcher(account.username()).matches()) {
                    findings.add(new Finding(
                        "ACC-NAME", ControlFamily.ACCOUNT_SECURITY, Severity.HIGH,
                        "Invalid account name", account.username(),
                        "Review account provisioning and apply the local naming policy."
                    ));
                }

                if (!names.add(account.username())) {
                    findings.add(new Finding(
                        "ACC-DUPLICATE", ControlFamily.ACCOUNT_SECURITY, Severity.HIGH,
                        "Duplicate account record", account.username(),
                        "Deduplicate the inventory and investigate provisioning."
                    ));
                }

                String previous = uidOwners.putIfAbsent(account.uid(), account.username());
                if (previous != null) {
                    findings.add(new Finding(
                        "ACC-UID-COLLISION", ControlFamily.ACCOUNT_SECURITY, Severity.HIGH,
                        "UID collision",
                        account.username() + " shares UID " + account.uid() + " with " + previous,
                        "Validate ownership and remove unintended UID sharing."
                    ));
                }

                if (account.uid() == 0 && !account.username().equals("root")) {
                    findings.add(new Finding(
                        "ACC-UID0", ControlFamily.ACCOUNT_SECURITY, Severity.CRITICAL,
                        "Unexpected UID 0 account", account.username(),
                        "Investigate immediately and remove unintended superuser privileges."
                    ));
                }

                if (account.username().equals("root") && !account.passwordLocked()) {
                    findings.add(new Finding(
                        "ACC-ROOT-PASSWORD", ControlFamily.ACCOUNT_SECURITY, Severity.HIGH,
                        "Root password is not locked", "root",
                        "Review direct root login and controlled privilege escalation."
                    ));
                }

                if (account.sudo() && account.serviceAccount()) {
                    findings.add(new Finding(
                        "ACC-SERVICE-SUDO", ControlFamily.ACCOUNT_SECURITY, Severity.HIGH,
                        "Privileged service account", account.username(),
                        "Remove unnecessary administrator privileges from service identities."
                    ));
                }

                if (account.interactive() && account.serviceAccount() &&
                    !account.shell().endsWith("nologin")) {
                    findings.add(new Finding(
                        "ACC-SERVICE-SHELL", ControlFamily.ACCOUNT_SECURITY, Severity.MEDIUM,
                        "Interactive service account",
                        account.username() + ": " + account.shell(),
                        "Use a non-login shell where the service design permits it."
                    ));
                }
            }

            return findings;
        }
    }

    static final class SshPolicyService {
        List<Finding> evaluate(SshPolicy ssh) {
            List<Finding> findings = new ArrayList<>();

            if (ssh.rootLoginAllowed()) {
                findings.add(new Finding(
                    "SSH-ROOT", ControlFamily.SSH_HARDENING, Severity.CRITICAL,
                    "Direct root login is enabled", "PermitRootLogin permits root",
                    "Disable root SSH login and validate an approved administrator account."
                ));
            }

            if (ssh.passwordAuthentication()) {
                findings.add(new Finding(
                    "SSH-PASSWORD", ControlFamily.SSH_HARDENING, Severity.HIGH,
                    "SSH password authentication enabled", "PasswordAuthentication=yes",
                    "Prefer managed public-key authentication or an approved stronger method."
                ));
            }

            if (!ssh.publicKeyAuthentication()) {
                findings.add(new Finding(
                    "SSH-PUBKEY", ControlFamily.SSH_HARDENING, Severity.HIGH,
                    "Public-key authentication disabled", "PubkeyAuthentication=no",
                    "Enable a reviewed authentication method and test recovery access."
                ));
            }

            if (ssh.maxAuthTries() > 4) {
                findings.add(new Finding(
                    "SSH-TRIES", ControlFamily.SSH_HARDENING, Severity.MEDIUM,
                    "Excessive authentication attempts",
                    "MaxAuthTries=" + ssh.maxAuthTries(),
                    "Use a small positive attempt limit."
                ));
            }

            if (ssh.allowedUsers().isEmpty()) {
                findings.add(new Finding(
                    "SSH-ALLOWLIST", ControlFamily.SSH_HARDENING, Severity.MEDIUM,
                    "No SSH allowlist", "Allowed-user set is empty",
                    "Define authorized accounts or groups after checking automation dependencies."
                ));
            }

            if (ssh.tcpForwarding()) {
                findings.add(new Finding(
                    "SSH-FORWARDING", ControlFamily.SSH_HARDENING, Severity.MEDIUM,
                    "TCP forwarding enabled", "AllowTcpForwarding=yes",
                    "Disable forwarding unless it is needed and appropriately restricted."
                ));
            }

            return findings;
        }
    }

    static final class FirewallPolicyService {
        List<Finding> evaluate(FirewallPolicy firewall) {
            List<Finding> findings = new ArrayList<>();
            Set<FirewallRule> seen = new HashSet<>();

            if (!Set.of("deny", "reject").contains(firewall.inboundDefault())) {
                findings.add(new Finding(
                    "FW-DEFAULT", ControlFamily.FIREWALLING, Severity.CRITICAL,
                    "Inbound default is permissive", firewall.inboundDefault(),
                    "Default to deny or reject and allow only required services."
                ));
            }

            if (firewall.forwardDefault().equals("allow")) {
                findings.add(new Finding(
                    "FW-FORWARD", ControlFamily.FIREWALLING, Severity.HIGH,
                    "Forwarding allowed by default", "Forward policy is allow",
                    "Restrict forwarding to documented routing requirements."
                ));
            }

            for (FirewallRule rule : firewall.rules()) {
                if (!Set.of("inbound", "outbound", "forward").contains(rule.direction())) {
                    findings.add(new Finding(
                        "FW-DIRECTION", ControlFamily.FIREWALLING, Severity.HIGH,
                        "Invalid rule direction", rule.direction(),
                        "Use inbound, outbound, or forward."
                    ));
                    continue;
                }

                if (!Set.of("allow", "deny", "reject").contains(rule.action())) {
                    findings.add(new Finding(
                        "FW-ACTION", ControlFamily.FIREWALLING, Severity.HIGH,
                        "Invalid rule action", rule.action(),
                        "Use allow, deny, or reject."
                    ));
                    continue;
                }

                if (!seen.add(rule)) {
                    findings.add(new Finding(
                        "FW-DUPLICATE", ControlFamily.FIREWALLING, Severity.LOW,
                        "Duplicate firewall rule", rule.toString(),
                        "Review rule ordering and remove redundant entries."
                    ));
                }

                if (rule.direction().equals("inbound") && rule.action().equals("allow") &&
                    rule.protocol().equals("tcp") && Objects.equals(rule.port(), 22) &&
                    Set.of("any", "0.0.0.0/0", "::/0").contains(rule.source())) {
                    findings.add(new Finding(
                        "FW-SSH-OPEN", ControlFamily.FIREWALLING, Severity.HIGH,
                        "SSH exposed to all sources", rule.source(),
                        "Restrict SSH to approved administrative networks or an access gateway."
                    ));
                }

                if (rule.direction().equals("inbound") && rule.action().equals("allow") &&
                    rule.port() != null && Set.of(23, 445, 3389).contains(rule.port()) &&
                    Set.of("any", "0.0.0.0/0", "::/0").contains(rule.source())) {
                    findings.add(new Finding(
                        "FW-SENSITIVE-PORT", ControlFamily.FIREWALLING, Severity.HIGH,
                        "Sensitive service exposed broadly", "Port " + rule.port(),
                        "Remove unnecessary exposure or restrict authorized source networks."
                    ));
                }
            }

            return findings;
        }
    }

    static final class MaintenancePolicyService {
        List<Finding> evaluate(PatchInventory patches, AuditInventory audit) {
            List<Finding> findings = new ArrayList<>();

            if (patches.criticalPending() > 0) {
                findings.add(new Finding(
                    "PATCH-CRITICAL", ControlFamily.PATCHING, Severity.CRITICAL,
                    "Critical updates pending", String.valueOf(patches.criticalPending()),
                    "Prioritize applicable fixes and install them through change control."
                ));
            } else if (patches.securityPending() > 0) {
                findings.add(new Finding(
                    "PATCH-SECURITY", ControlFamily.PATCHING, Severity.HIGH,
                    "Security updates pending", String.valueOf(patches.securityPending()),
                    "Prioritize patches according to severity and exposure."
                ));
            }

            if (patches.daysSinceSuccessfulUpdate() > 30) {
                findings.add(new Finding(
                    "PATCH-STALE", ControlFamily.PATCHING, Severity.HIGH,
                    "Patch process is stale",
                    patches.daysSinceSuccessfulUpdate() + " days",
                    "Investigate failed jobs and restore the approved patch cadence."
                ));
            }

            if (patches.rebootRequired()) {
                findings.add(new Finding(
                    "PATCH-REBOOT", ControlFamily.PATCHING, Severity.HIGH,
                    "Reboot pending", "A restart is required",
                    "Schedule a controlled restart and verify service health."
                ));
            }

            if (!patches.unattendedUpdatesEnabled()) {
                findings.add(new Finding(
                    "PATCH-AUTOMATION", ControlFamily.PATCHING, Severity.MEDIUM,
                    "Automated updates disabled", "No unattended update policy",
                    "Enable appropriate automation or document an equivalent managed process."
                ));
            }

            if (!audit.auditdEnabled() || !audit.authenticationLogs()) {
                findings.add(new Finding(
                    "AUDIT-COLLECTION", ControlFamily.AUDITING, Severity.HIGH,
                    "Audit collection is incomplete",
                    "auditd=" + audit.auditdEnabled() +
                        ", authLogs=" + audit.authenticationLogs(),
                    "Enable audit collection and authentication logging."
                ));
            }

            if (!audit.persistentRules() || !audit.timeSynchronization() ||
                !audit.integrityMonitoring()) {
                findings.add(new Finding(
                    "AUDIT-TELEMETRY", ControlFamily.AUDITING, Severity.MEDIUM,
                    "Audit telemetry has gaps",
                    "Persistent rules, time synchronization, or integrity monitoring is disabled",
                    "Persist reviewed rules, synchronize time, and monitor critical files."
                ));
            }

            if (audit.retentionDays() < 30) {
                findings.add(new Finding(
                    "AUDIT-RETENTION", ControlFamily.AUDITING, Severity.MEDIUM,
                    "Short log retention", audit.retentionDays() + " days",
                    "Define retention from incident-response, legal, and storage requirements."
                ));
            }

            return findings;
        }
    }

    static final class ChangeRequest {
        private final String id;
        private final String owner;
        private ChangeStatus status = ChangeStatus.PROPOSED;
        private final List<Instant> transitions = new ArrayList<>();

        ChangeRequest(String id, String owner) {
            if (id == null || id.isBlank() || owner == null || owner.isBlank()) {
                throw new IllegalArgumentException("Change ID and owner are required.");
            }
            this.id = id;
            this.owner = owner;
            transitions.add(Instant.now());
        }

        void transition(ChangeStatus next) {
            boolean allowed = switch (status) {
                case PROPOSED -> next == ChangeStatus.APPROVED || next == ChangeStatus.FAILED;
                case APPROVED -> next == ChangeStatus.SCHEDULED || next == ChangeStatus.FAILED;
                case SCHEDULED -> next == ChangeStatus.EXECUTING || next == ChangeStatus.FAILED;
                case EXECUTING -> next == ChangeStatus.VERIFIED ||
                                  next == ChangeStatus.FAILED ||
                                  next == ChangeStatus.ROLLED_BACK;
                case FAILED -> next == ChangeStatus.PROPOSED;
                case ROLLED_BACK -> next == ChangeStatus.PROPOSED;
                case VERIFIED -> false;
            };

            if (!allowed) {
                throw new IllegalStateException(
                    "Invalid change transition: " + status + " -> " + next
                );
            }

            status = next;
            transitions.add(Instant.now());
        }

        String description() {
            return id + " owner=" + owner + " status=" + status +
                " transitions=" + transitions.size();
        }
    }

    static final class AssessmentService {
        private final AccountPolicy accounts = new AccountPolicy();
        private final SshPolicyService ssh = new SshPolicyService();
        private final FirewallPolicyService firewall = new FirewallPolicyService();
        private final MaintenancePolicyService maintenance = new MaintenancePolicyService();

        List<Finding> assess(Server server) {
            List<Finding> findings = new ArrayList<>();
            findings.addAll(accounts.evaluate(server.accounts()));
            findings.addAll(ssh.evaluate(server.ssh()));
            findings.addAll(firewall.evaluate(server.firewall()));
            findings.addAll(maintenance.evaluate(server.patches(), server.audit()));

            findings.sort(
                Comparator.comparing(Finding::severity)
                    .thenComparing(Finding::family)
                    .thenComparing(Finding::controlId)
            );

            return List.copyOf(findings);
        }
    }

    private static Server exampleServer() {
        List<Account> accounts = List.of(
            new Account("root", 0, true, true, true, false, "/bin/bash", Set.of()),
            new Account("platform", 1000, false, true, true, false,
                "/bin/bash", Set.of("sudo", "adm")),
            new Account("pipeline", 1001, true, true, true, true,
                "/bin/bash", Set.of("deploy")),
            new Account("metrics", 1002, true, false, false, true,
                "/usr/sbin/nologin", Set.of("metrics"))
        );

        SshPolicy ssh = new SshPolicy(
            false, true, true, true, 6, Set.of("platform", "pipeline")
        );

        FirewallPolicy firewall = new FirewallPolicy(
            "allow", "allow", "deny",
            List.of(
                new FirewallRule("inbound", "allow", "tcp", 22, "0.0.0.0/0"),
                new FirewallRule("inbound", "allow", "tcp", 443, "0.0.0.0/0"),
                new FirewallRule("inbound", "allow", "tcp", 23, "0.0.0.0/0")
            )
        );

        PatchInventory patches = new PatchInventory(2, 10, 38, true, false);
        AuditInventory audit = new AuditInventory(false, false, true, true, false, 14);

        return new Server("billing-prod-01", accounts, ssh, firewall, patches, audit);
    }

    public static void main(String[] args) {
        Server server = exampleServer();
        AssessmentService assessment = new AssessmentService();
        List<Finding> findings = assessment.assess(server);

        Map<Severity, Long> counts = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            counts.put(severity, findings.stream()
                .filter(finding -> finding.severity() == severity)
                .count());
        }

        System.out.println("Enterprise Linux hardening assessment");
        System.out.println("Host: " + server.hostname());
        System.out.println("Assessment time: " + Instant.now());
        System.out.println("Findings: " + findings.size());
        System.out.println("Severity distribution: " + counts);

        for (Finding finding : findings) {
            System.out.printf(
                "%n[%s] %s (%s)%nEvidence: %s%nRemediation: %s%n",
                finding.severity(),
                finding.title(),
                finding.controlId(),
                finding.evidence(),
                finding.remediation()
            );
        }

        ChangeRequest patchChange = new ChangeRequest("CHG-2026-1042", "platform-team");
        patchChange.transition(ChangeStatus.APPROVED);
        patchChange.transition(ChangeStatus.SCHEDULED);
        patchChange.transition(ChangeStatus.EXECUTING);
        patchChange.transition(ChangeStatus.VERIFIED);
        System.out.println("\nVerified change: " + patchChange.description());

        try {
            patchChange.transition(ChangeStatus.PROPOSED);
        } catch (IllegalStateException expected) {
            System.out.println("Invalid change transition rejected: " + expected.getMessage());
        }

        boolean criticalPresent = findings.stream()
            .anyMatch(finding -> finding.severity() == Severity.CRITICAL);

        System.out.println(
            "\nRelease decision: " +
            (criticalPresent
                ? "review critical findings before deployment"
                : "continue with the approved operational process")
        );
    }
}
