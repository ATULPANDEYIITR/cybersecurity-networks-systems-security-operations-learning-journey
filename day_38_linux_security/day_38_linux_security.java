import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/*
 * Linux Security Governance Model
 *
 * Enterprise-oriented Java 17 implementation covering:
 * SSH access policy, sudo command authorization, filesystem permissions,
 * secure host configuration, and service minimization.
 *
 * The program evaluates a model of a Linux host and never changes the
 * operating system on which it is executed.
 */
public class LinuxSecurityGovernance {

    enum Severity {
        INFO(0),
        LOW(2),
        MEDIUM(5),
        HIGH(10),
        CRITICAL(20);

        private final int penalty;

        Severity(int penalty) {
            this.penalty = penalty;
        }

        int penalty() {
            return penalty;
        }
    }

    enum AuthenticationMethod {
        PASSWORD,
        PUBLIC_KEY,
        CERTIFICATE
    }

    enum ReviewDecision {
        ALLOW,
        DENY
    }

    record Finding(
            String area,
            Severity severity,
            String title,
            String detail,
            String recommendation
    ) {}

    record UserAccount(
            String username,
            Set<String> groups,
            boolean root,
            boolean locked,
            boolean publicKeyConfigured
    ) {
        UserAccount {
            groups = Set.copyOf(groups);
        }
    }

    record SshRequest(
            String username,
            AuthenticationMethod method,
            int attempts
    ) {}

    record SshPolicy(
            boolean permitRootLogin,
            boolean passwordAuthentication,
            boolean publicKeyAuthentication,
            Set<String> allowedUsers,
            Set<String> allowedGroups,
            int maxAuthTries,
            boolean x11Forwarding,
            boolean agentForwarding,
            boolean tcpForwarding
    ) {
        SshPolicy {
            allowedUsers = Set.copyOf(allowedUsers);
            allowedGroups = Set.copyOf(allowedGroups);

            if (maxAuthTries < 1) {
                throw new IllegalArgumentException(
                        "SSH authentication retry limit must be positive."
                );
            }
        }

        EvaluationResult evaluate(
                UserAccount account,
                SshRequest request
        ) {
            if (account == null) {
                return EvaluationResult.deny("Unknown account.");
            }

            if (account.locked()) {
                return EvaluationResult.deny("Account is locked.");
            }

            if (account.root() && !permitRootLogin) {
                return EvaluationResult.deny(
                        "Direct root SSH login is disabled."
                );
            }

            if (!allowedUsers.isEmpty() &&
                    !allowedUsers.contains(account.username())) {
                return EvaluationResult.deny(
                        "Account is outside the allowed SSH users."
                );
            }

            boolean allowedGroup = account.groups()
                    .stream()
                    .anyMatch(allowedGroups::contains);

            if (!allowedGroups.isEmpty() && !allowedGroup) {
                return EvaluationResult.deny(
                        "Account is outside the allowed SSH groups."
                );
            }

            if (request.attempts() > maxAuthTries) {
                return EvaluationResult.deny(
                        "Maximum authentication attempts exceeded."
                );
            }

            if (request.method() == AuthenticationMethod.PASSWORD &&
                    !passwordAuthentication) {
                return EvaluationResult.deny(
                        "Password authentication is disabled."
                );
            }

            if (request.method() == AuthenticationMethod.PUBLIC_KEY) {
                if (!publicKeyAuthentication) {
                    return EvaluationResult.deny(
                            "Public-key authentication is disabled."
                    );
                }

                if (!account.publicKeyConfigured()) {
                    return EvaluationResult.deny(
                            "No public key is configured for this account."
                    );
                }
            }

            return EvaluationResult.allow(
                    "SSH policy permits the connection."
            );
        }

        List<Finding> audit() {
            List<Finding> findings = new ArrayList<>();

            if (permitRootLogin) {
                findings.add(new Finding(
                        "SSH",
                        Severity.CRITICAL,
                        "Direct root login enabled",
                        "Remote users can authenticate directly as root.",
                        "Disable direct root SSH login."
                ));
            }

            if (passwordAuthentication) {
                findings.add(new Finding(
                        "SSH",
                        Severity.HIGH,
                        "Password authentication enabled",
                        "The daemon accepts password authentication.",
                        "Prefer public-key authentication."
                ));
            }

            if (maxAuthTries > 4) {
                findings.add(new Finding(
                        "SSH",
                        Severity.MEDIUM,
                        "High authentication retry limit",
                        "The SSH retry threshold is unnecessarily permissive.",
                        "Use a restrictive authentication attempt limit."
                ));
            }

            if (x11Forwarding) {
                findings.add(new Finding(
                        "SSH",
                        Severity.MEDIUM,
                        "X11 forwarding enabled",
                        "SSH clients may request X11 forwarding.",
                        "Disable X11 forwarding unless explicitly required."
                ));
            }

            if (agentForwarding) {
                findings.add(new Finding(
                        "SSH",
                        Severity.MEDIUM,
                        "Agent forwarding enabled",
                        "Forwarded agent credentials can be exposed by compromised hosts.",
                        "Disable agent forwarding unless operationally required."
                ));
            }

            if (tcpForwarding) {
                findings.add(new Finding(
                        "SSH",
                        Severity.MEDIUM,
                        "TCP forwarding enabled",
                        "SSH users can establish tunnels.",
                        "Disable forwarding unless explicitly authorized."
                ));
            }

            return findings;
        }
    }

    record SudoRule(
            Set<String> users,
            Set<String> commands,
            boolean requirePassword,
            boolean noExec
    ) {
        SudoRule {
            users = Set.copyOf(users);
            commands = Set.copyOf(commands);
        }

        boolean matches(String username, String command) {
            boolean userMatches =
                    users.contains("ALL") || users.contains(username);

            boolean commandMatches =
                    commands.contains("ALL") || commands.contains(command);

            return userMatches && commandMatches;
        }
    }

    static final class SudoPolicy {
        private final List<SudoRule> rules;

        SudoPolicy(List<SudoRule> rules) {
            this.rules = List.copyOf(rules);
        }

        EvaluationResult authorize(String username, String command) {
            return rules.stream()
                    .filter(rule -> rule.matches(username, command))
                    .findFirst()
                    .map(rule -> EvaluationResult.allow(
                            "Authorized; passwordRequired=" +
                                    rule.requirePassword() +
                                    ", noExec=" +
                                    rule.noExec()
                    ))
                    .orElseGet(() -> EvaluationResult.deny(
                            "No sudo rule authorizes this command."
                    ));
        }

        List<Finding> audit() {
            List<Finding> findings = new ArrayList<>();

            for (SudoRule rule : rules) {
                if (rule.users().contains("ALL") &&
                        rule.commands().contains("ALL")) {
                    findings.add(new Finding(
                            "sudo",
                            Severity.CRITICAL,
                            "Unrestricted sudo rule",
                            "All users can execute all commands.",
                            "Replace unrestricted authorization with explicit commands."
                    ));
                } else if (rule.commands().contains("ALL")) {
                    findings.add(new Finding(
                            "sudo",
                            Severity.HIGH,
                            "Broad sudo command scope",
                            "The rule permits arbitrary command execution.",
                            "Apply least privilege to the command set."
                    ));
                }

                if (!rule.requirePassword()) {
                    findings.add(new Finding(
                            "sudo",
                            Severity.MEDIUM,
                            "Passwordless sudo",
                            "The rule permits execution without password authentication.",
                            "Use NOPASSWD only for tightly controlled automation."
                    ));
                }
            }

            return findings;
        }
    }

    enum FileAction {
        READ(4),
        WRITE(2),
        EXECUTE(1);

        private final int bit;

        FileAction(int bit) {
            this.bit = bit;
        }

        int bit() {
            return bit;
        }
    }

    record FileObject(
            String path,
            String owner,
            String group,
            int mode,
            boolean directory
    ) {}

    static final class PermissionService {
        private final Map<String, FileObject> files = new HashMap<>();

        PermissionService(List<FileObject> objects) {
            for (FileObject object : objects) {
                if (files.put(object.path(), object) != null) {
                    throw new IllegalArgumentException(
                            "Duplicate path: " + object.path()
                    );
                }
            }
        }

        EvaluationResult authorize(
                String path,
                String username,
                Set<String> groups,
                FileAction action
        ) {
            FileObject object = files.get(path);

            if (object == null) {
                return EvaluationResult.deny(
                        "Path does not exist in the model."
                );
            }

            int available;
            String permissionClass;

            if (object.owner().equals(username)) {
                available = (object.mode() >> 6) & 7;
                permissionClass = "owner";
            } else if (groups.contains(object.group())) {
                available = (object.mode() >> 3) & 7;
                permissionClass = "group";
            } else {
                available = object.mode() & 7;
                permissionClass = "other";
            }

            if ((available & action.bit()) == action.bit()) {
                return EvaluationResult.allow(
                        "Allowed by " + permissionClass + " permission bits."
                );
            }

            return EvaluationResult.deny(
                    "Denied by " + permissionClass + " permission bits."
            );
        }

        List<Finding> audit() {
            List<Finding> findings = new ArrayList<>();

            for (FileObject object : files.values()) {
                int basicMode = object.mode() & 0777;

                if ((basicMode & 0002) != 0) {
                    findings.add(new Finding(
                            "Permissions",
                            Severity.HIGH,
                            "World-writable object",
                            object.path() + " permits writes by other users.",
                            "Remove unnecessary other-user write access."
                    ));
                }

                if (!object.directory() && (basicMode & 0004) != 0) {
                    findings.add(new Finding(
                            "Permissions",
                            Severity.MEDIUM,
                            "World-readable file",
                            object.path() + " can be read by other users.",
                            "Restrict sensitive file access."
                    ));
                }

                if ((object.mode() & 04000) != 0) {
                    findings.add(new Finding(
                            "Permissions",
                            Severity.HIGH,
                            "Setuid executable",
                            object.path() +
                                    " executes with the owner's effective privileges.",
                            "Verify that the privileged executable is required."
                    ));
                }
            }

            return findings;
        }
    }

    record HostConfiguration(
            boolean firewallEnabled,
            boolean automaticSecurityUpdates,
            boolean auditLogging,
            boolean timeSynchronization,
            boolean coreDumpsRestricted,
            boolean kernelModulesRestricted,
            boolean fileIntegrityMonitoring,
            boolean secureBoot
    ) {}

    static final class ConfigurationService {
        private final HostConfiguration configuration;

        ConfigurationService(HostConfiguration configuration) {
            this.configuration = configuration;
        }

        List<Finding> audit() {
            List<Finding> findings = new ArrayList<>();

            if (!configuration.firewallEnabled()) {
                findings.add(new Finding(
                        "Secure configuration",
                        Severity.HIGH,
                        "Firewall disabled",
                        "Local network exposure is not constrained.",
                        "Enable a host firewall."
                ));
            }

            if (!configuration.automaticSecurityUpdates()) {
                findings.add(new Finding(
                        "Secure configuration",
                        Severity.MEDIUM,
                        "Security updates disabled",
                        "Security fixes may remain unapplied.",
                        "Use controlled automatic security updates or equivalent patch management."
                ));
            }

            if (!configuration.auditLogging()) {
                findings.add(new Finding(
                        "Secure configuration",
                        Severity.HIGH,
                        "Audit logging disabled",
                        "Important security events may be unavailable.",
                        "Enable security and system auditing."
                ));
            }

            if (!configuration.timeSynchronization()) {
                findings.add(new Finding(
                        "Secure configuration",
                        Severity.MEDIUM,
                        "Time synchronization disabled",
                        "Security event timelines can become unreliable.",
                        "Use trusted time synchronization."
                ));
            }

            if (!configuration.coreDumpsRestricted()) {
                findings.add(new Finding(
                        "Secure configuration",
                        Severity.MEDIUM,
                        "Core dumps unrestricted",
                        "Crash artifacts may expose process memory.",
                        "Restrict core dumps."
                ));
            }

            if (!configuration.kernelModulesRestricted()) {
                findings.add(new Finding(
                        "Secure configuration",
                        Severity.MEDIUM,
                        "Kernel module loading unrestricted",
                        "Privileged kernel extensions increase attack surface.",
                        "Restrict module loading where appropriate."
                ));
            }

            if (!configuration.fileIntegrityMonitoring()) {
                findings.add(new Finding(
                        "Secure configuration",
                        Severity.MEDIUM,
                        "File integrity monitoring disabled",
                        "Unauthorized modifications may go undetected.",
                        "Monitor critical configuration and executable paths."
                ));
            }

            if (!configuration.secureBoot()) {
                findings.add(new Finding(
                        "Secure configuration",
                        Severity.LOW,
                        "Secure Boot disabled",
                        "Firmware-level boot-chain verification is unavailable.",
                        "Enable Secure Boot when platform requirements permit it."
                ));
            }

            return findings;
        }
    }

    record Service(
            String name,
            boolean enabledAtBoot,
            Set<Integer> ports,
            boolean businessRequired,
            boolean remotelyReachable
    ) {
        Service {
            ports = Set.copyOf(ports);
        }
    }

    static final class ServiceMinimizationService {
        private final List<Service> services;

        ServiceMinimizationService(List<Service> services) {
            this.services = List.copyOf(services);
        }

        List<Finding> audit() {
            List<Finding> findings = new ArrayList<>();

            for (Service service : services) {
                if (!service.businessRequired() && service.enabledAtBoot()) {
                    findings.add(new Finding(
                            "Services",
                            Severity.HIGH,
                            "Unnecessary enabled service",
                            service.name() +
                                    " starts automatically without a business requirement.",
                            "Disable or remove the service."
                    ));
                }

                if (!service.businessRequired() &&
                        !service.ports().isEmpty()) {
                    findings.add(new Finding(
                            "Services",
                            Severity.HIGH,
                            "Unnecessary network listener",
                            service.name() +
                                    " exposes network listeners without a business requirement.",
                            "Stop the service or remove unnecessary listeners."
                    ));
                }

                if (service.remotelyReachable() &&
                        !service.ports().isEmpty()) {
                    findings.add(new Finding(
                            "Services",
                            Severity.MEDIUM,
                            "Remote service exposure",
                            service.name() +
                                    " is remotely reachable.",
                            "Verify every exposed listener is necessary."
                    ));
                }
            }

            return findings;
        }
    }

    record EvaluationResult(
            ReviewDecision decision,
            String reason
    ) {
        static EvaluationResult allow(String reason) {
            return new EvaluationResult(ReviewDecision.ALLOW, reason);
        }

        static EvaluationResult deny(String reason) {
            return new EvaluationResult(ReviewDecision.DENY, reason);
        }
    }

    static final class GovernanceService {
        private final SshPolicy sshPolicy;
        private final SudoPolicy sudoPolicy;
        private final PermissionService permissionService;
        private final ConfigurationService configurationService;
        private final ServiceMinimizationService serviceService;

        GovernanceService(
                SshPolicy sshPolicy,
                SudoPolicy sudoPolicy,
                PermissionService permissionService,
                ConfigurationService configurationService,
                ServiceMinimizationService serviceService
        ) {
            this.sshPolicy = sshPolicy;
            this.sudoPolicy = sudoPolicy;
            this.permissionService = permissionService;
            this.configurationService = configurationService;
            this.serviceService = serviceService;
        }

        List<Finding> findings() {
            List<Finding> findings = new ArrayList<>();

            findings.addAll(sshPolicy.audit());
            findings.addAll(sudoPolicy.audit());
            findings.addAll(permissionService.audit());
            findings.addAll(configurationService.audit());
            findings.addAll(serviceService.audit());

            return findings;
        }

        int securityScore() {
            int penalty = findings()
                    .stream()
                    .mapToInt(finding -> finding.severity().penalty())
                    .sum();

            return Math.max(0, 100 - penalty);
        }

        void printReport() {
            List<Finding> findings = findings();

            System.out.println("\n=== Enterprise Linux Security Report ===");
            System.out.println(
                    "Security posture score: " + securityScore() + "/100"
            );

            for (Finding finding : findings) {
                System.out.println();
                System.out.println(
                        "[" + finding.severity() + "] " +
                                finding.area() + ": " +
                                finding.title()
                );
                System.out.println("    " + finding.detail());
                System.out.println(
                        "    Recommendation: " +
                                finding.recommendation()
                );
            }
        }
    }

    public static void main(String[] args) {
        Map<String, UserAccount> accounts = new HashMap<>();

        accounts.put(
                "opsadmin",
                new UserAccount(
                        "opsadmin",
                        Set.of("linux-admins"),
                        false,
                        false,
                        true
                )
        );

        accounts.put(
                "developer",
                new UserAccount(
                        "developer",
                        Set.of("developers"),
                        false,
                        false,
                        true
                )
        );

        accounts.put(
                "legacy",
                new UserAccount(
                        "legacy",
                        Set.of("legacy-users"),
                        false,
                        false,
                        false
                )
        );

        accounts.put(
                "root",
                new UserAccount(
                        "root",
                        Set.of("root"),
                        true,
                        false,
                        true
                )
        );

        SshPolicy sshPolicy = new SshPolicy(
                false,
                false,
                true,
                Set.of("opsadmin", "developer"),
                Set.of("linux-admins"),
                3,
                false,
                false,
                false
        );

        SudoPolicy sudoPolicy = new SudoPolicy(List.of(
                new SudoRule(
                        Set.of("opsadmin"),
                        Set.of(
                                "/usr/bin/systemctl restart nginx",
                                "/usr/bin/systemctl status nginx"
                        ),
                        true,
                        true
                ),
                new SudoRule(
                        Set.of("developer"),
                        Set.of("/usr/bin/journalctl"),
                        true,
                        true
                )
        ));

        PermissionService permissionService = new PermissionService(List.of(
                new FileObject(
                        "/etc/ssh/sshd_config",
                        "root",
                        "root",
                        0600,
                        false
                ),
                new FileObject(
                        "/etc/shadow",
                        "root",
                        "shadow",
                        0640,
                        false
                ),
                new FileObject(
                        "/srv/application",
                        "deploy",
                        "app",
                        0750,
                        true
                ),
                new FileObject(
                        "/tmp/uploads",
                        "deploy",
                        "app",
                        0777,
                        true
                ),
                new FileObject(
                        "/usr/local/bin/privileged-helper",
                        "root",
                        "root",
                        04755,
                        false
                )
        ));

        ConfigurationService configurationService =
                new ConfigurationService(
                        new HostConfiguration(
                                true,
                                true,
                                true,
                                true,
                                true,
                                true,
                                false,
                                true
                        )
                );

        ServiceMinimizationService serviceService =
                new ServiceMinimizationService(List.of(
                        new Service(
                                "sshd",
                                true,
                                Set.of(22),
                                true,
                                true
                        ),
                        new Service(
                                "nginx",
                                true,
                                Set.of(443),
                                true,
                                true
                        ),
                        new Service(
                                "telnet",
                                true,
                                Set.of(23),
                                false,
                                true
                        ),
                        new Service(
                                "cups",
                                true,
                                Set.of(631),
                                false,
                                false
                        )
                ));

        GovernanceService governance = new GovernanceService(
                sshPolicy,
                sudoPolicy,
                permissionService,
                configurationService,
                serviceService
        );

        System.out.println("Linux Security Governance Engine");
        System.out.println(
                "Enterprise policy model; no host settings are modified."
        );

        System.out.println("\n=== SSH Decisions ===");

        List<SshRequest> sshRequests = List.of(
                new SshRequest(
                        "opsadmin",
                        AuthenticationMethod.PUBLIC_KEY,
                        1
                ),
                new SshRequest(
                        "legacy",
                        AuthenticationMethod.PASSWORD,
                        1
                ),
                new SshRequest(
                        "root",
                        AuthenticationMethod.PUBLIC_KEY,
                        1
                ),
                new SshRequest(
                        "opsadmin",
                        AuthenticationMethod.PUBLIC_KEY,
                        5
                )
        );

        for (SshRequest request : sshRequests) {
            EvaluationResult result = sshPolicy.evaluate(
                    accounts.get(request.username()),
                    request
            );

            System.out.println(
                    result.decision() + " " +
                            request.username() +
                            " -> " +
                            result.reason()
            );
        }

        System.out.println("\n=== sudo Decisions ===");

        List<String[]> sudoRequests = List.of(
                new String[]{
                        "opsadmin",
                        "/usr/bin/systemctl restart nginx"
                },
                new String[]{
                        "opsadmin",
                        "/bin/bash"
                },
                new String[]{
                        "developer",
                        "/usr/bin/journalctl"
                }
        );

        for (String[] request : sudoRequests) {
            EvaluationResult result = sudoPolicy.authorize(
                    request[0],
                    request[1]
            );

            System.out.println(
                    result.decision() + " " +
                            request[0] + " -> " +
                            request[1] + ": " +
                            result.reason()
            );
        }

        System.out.println("\n=== Permission Decisions ===");

        List<String[]> permissionRequests = List.of(
                new String[]{
                        "/etc/ssh/sshd_config",
                        "developer",
                        "read"
                },
                new String[]{
                        "/etc/ssh/sshd_config",
                        "root",
                        "read"
                },
                new String[]{
                        "/tmp/uploads",
                        "developer",
                        "write"
                }
        );

        for (String[] request : permissionRequests) {
            Set<String> groups = request[1].equals("root")
                    ? Set.of("root")
                    : Set.of("developers");

            EvaluationResult result = permissionService.authorize(
                    request[0],
                    request[1],
                    groups,
                    FileAction.valueOf(request[2].toUpperCase())
            );

            System.out.println(
                    result.decision() + " " +
                            request[1] + " " +
                            request[2] + " " +
                            request[0] + ": " +
                            result.reason()
            );
        }

        governance.printReport();
    }
}
