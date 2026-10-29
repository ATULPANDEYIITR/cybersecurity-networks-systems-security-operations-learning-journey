import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.HashSet;
import java.util.regex.Pattern;

public class HostFirewallEnterprise {

    enum Direction {
        INBOUND, OUTBOUND
    }

    enum Action {
        ALLOW, DENY
    }

    enum Protocol {
        TCP, UDP, ICMP, ANY
    }

    enum LogLevel {
        NONE, DENIED, ALL
    }

    record Connection(
            Direction direction,
            Protocol protocol,
            String sourceIp,
            String destinationIp,
            Integer sourcePort,
            Integer destinationPort,
            String application,
            String user
    ) {}

    record FirewallRule(
            String id,
            Direction direction,
            Action action,
            Protocol protocol,
            String sourceNetwork,
            String destinationNetwork,
            Integer destinationPort,
            String application,
            int priority,
            boolean enabled,
            LogLevel logLevel,
            String description
    ) {
        FirewallRule {
            if (id == null || id.isBlank()) {
                throw new IllegalArgumentException("Rule id is required");
            }
            if (priority < 1) {
                throw new IllegalArgumentException("Priority must be positive");
            }
            validatePort(destinationPort);
            Objects.requireNonNull(direction);
            Objects.requireNonNull(action);
            Objects.requireNonNull(protocol);
            Objects.requireNonNull(logLevel);
            IPv4Network.parse(sourceNetwork);
            IPv4Network.parse(destinationNetwork);
        }
    }

    record ReviewEvent(
            Instant timestamp,
            String ruleId,
            Action action,
            String application,
            String reason
    ) {}

    record MergePolicy(
            Set<String> trustedApplications,
            Set<Integer> approvedPorts,
            int maximumPriorityForAdministrativeRules
    ) {}

    static final class IPv4Network {
        private final long network;
        private final long mask;

        private IPv4Network(long network, long mask) {
            this.network = network;
            this.mask = mask;
        }

        static IPv4Network parse(String cidr) {
            String[] parts = cidr.split("/", -1);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid CIDR: " + cidr);
            }

            int prefix;
            try {
                prefix = Integer.parseInt(parts[1]);
            } catch (NumberFormatException error) {
                throw new IllegalArgumentException("Invalid CIDR prefix");
            }

            if (prefix < 0 || prefix > 32) {
                throw new IllegalArgumentException("CIDR prefix must be 0..32");
            }

            long address = parseAddress(parts[0]);
            long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;

            return new IPv4Network(address & mask, mask);
        }

        private static long parseAddress(String value) {
            String[] octets = value.split("\\.", -1);
            if (octets.length != 4) {
                throw new IllegalArgumentException("Invalid IPv4 address: " + value);
            }

            long result = 0;
            for (String octet : octets) {
                int number;
                try {
                    number = Integer.parseInt(octet);
                } catch (NumberFormatException error) {
                    throw new IllegalArgumentException("Invalid IPv4 address: " + value);
                }

                if (number < 0 || number > 255) {
                    throw new IllegalArgumentException("Invalid IPv4 octet");
                }

                result = (result << 8) | number;
            }
            return result;
        }

        boolean contains(String address) {
            return (parseAddress(address) & mask) == network;
        }
    }

    static final class PolicyViolationException extends Exception {
        PolicyViolationException(String message) {
            super(message);
        }
    }

    interface RulePolicy {
        void validate(Connection connection, FirewallRule rule)
                throws PolicyViolationException;
    }

    static final class EnterprisePolicy implements RulePolicy {
        private final MergePolicy policy;

        EnterprisePolicy(MergePolicy policy) {
            this.policy = policy;
        }

        @Override
        public void validate(Connection connection, FirewallRule rule)
                throws PolicyViolationException {

            if (connection.direction() == Direction.OUTBOUND
                    && rule.action() == Action.ALLOW
                    && !policy.trustedApplications().contains(connection.application())) {
                throw new PolicyViolationException(
                        "Outbound allow is not permitted for untrusted application"
                );
            }

            if (rule.destinationPort() != null
                    && connection.destinationPort() != null
                    && !policy.approvedPorts().contains(connection.destinationPort())
                    && rule.action() == Action.ALLOW) {
                throw new PolicyViolationException(
                        "Destination port is outside the enterprise allow list"
                );
            }

            if (rule.priority() <= policy.maximumPriorityForAdministrativeRules()
                    && connection.direction() != Direction.INBOUND) {
                throw new PolicyViolationException(
                        "Administrative priority is reserved for inbound controls"
                );
            }
        }
    }

    static final class FirewallService {
        private final List<FirewallRule> rules = new ArrayList<>();
        private final List<ReviewEvent> events = new ArrayList<>();
        private final RulePolicy policy;
        private final Action defaultAction;

        FirewallService(Action defaultAction, RulePolicy policy) {
            this.defaultAction = Objects.requireNonNull(defaultAction);
            this.policy = Objects.requireNonNull(policy);
        }

        void registerRule(FirewallRule rule) {
            if (rules.stream().anyMatch(existing -> existing.id().equals(rule.id()))) {
                throw new IllegalArgumentException("Duplicate rule: " + rule.id());
            }

            rules.add(rule);
            rules.sort(Comparator.comparingInt(FirewallRule::priority));
        }

        Decision evaluate(Connection connection) throws PolicyViolationException {
            validateConnection(connection);

            Optional<FirewallRule> matching = rules.stream()
                    .filter(rule -> rule.enabled() && matches(connection, rule))
                    .findFirst();

            if (matching.isEmpty()) {
                Decision decision = new Decision(
                        defaultAction,
                        "DEFAULT",
                        defaultAction == Action.DENY,
                        "No explicit rule matched"
                );
                if (decision.logged()) {
                    record(connection, decision);
                }
                return decision;
            }

            FirewallRule rule = matching.get();
            policy.validate(connection, rule);

            boolean logged =
                    rule.logLevel() == LogLevel.ALL
                            || (rule.logLevel() == LogLevel.DENIED
                                && rule.action() == Action.DENY);

            Decision decision = new Decision(
                    rule.action(),
                    rule.id(),
                    logged,
                    rule.description()
            );

            if (logged) {
                record(connection, decision);
            }

            return decision;
        }

        private boolean matches(Connection connection, FirewallRule rule) {
            if (connection.direction() != rule.direction()) return false;
            if (rule.protocol() != Protocol.ANY
                    && connection.protocol() != rule.protocol()) return false;

            if (!IPv4Network.parse(rule.sourceNetwork()).contains(connection.sourceIp())) {
                return false;
            }

            if (!IPv4Network.parse(rule.destinationNetwork())
                    .contains(connection.destinationIp())) {
                return false;
            }

            if (rule.destinationPort() != null
                    && !Objects.equals(rule.destinationPort(), connection.destinationPort())) {
                return false;
            }

            return applicationMatches(connection.application(), rule.application());
        }

        private boolean applicationMatches(String application, String pattern) {
            if ("*".equals(pattern)) return true;

            String regex = Pattern.quote(pattern).replace("\\*", "\\E.*\\Q");
            return application.matches(regex);
        }

        private void record(Connection connection, Decision decision) {
            events.add(new ReviewEvent(
                    Instant.now(),
                    decision.ruleId(),
                    decision.action(),
                    connection.application(),
                    decision.reason()
            ));
        }

        List<ReviewEvent> auditEvents() {
            return List.copyOf(events);
        }
    }

    record Decision(
            Action action,
            String ruleId,
            boolean logged,
            String reason
    ) {}

    static void validateConnection(Connection connection) {
        Objects.requireNonNull(connection);
        IPv4Network.parse(connection.sourceIp() + "/32");
        IPv4Network.parse(connection.destinationIp() + "/32");

        validatePort(connection.sourcePort());
        validatePort(connection.destinationPort());

        if (connection.application() == null || connection.application().isBlank()) {
            throw new IllegalArgumentException("Application is required");
        }
    }

    static void validatePort(Integer port) {
        if (port != null && (port < 1 || port > 65535)) {
            throw new IllegalArgumentException("Port must be 1..65535");
        }
    }

    static FirewallRule rule(
            String id,
            Direction direction,
            Action action,
            Protocol protocol,
            String source,
            String destination,
            Integer port,
            String application,
            int priority,
            LogLevel level,
            String description
    ) {
        return new FirewallRule(
                id,
                direction,
                action,
                protocol,
                source,
                destination,
                port,
                application,
                priority,
                true,
                level,
                description
        );
    }

    public static void main(String[] args) {
        try {
            MergePolicy policy = new MergePolicy(
                    Set.of("sshd", "resolver", "browser"),
                    Set.of(22, 53, 443),
                    20
            );

            FirewallService service =
                    new FirewallService(Action.DENY, new EnterprisePolicy(policy));

            service.registerRule(rule(
                    "ALLOW-SSH-MGMT",
                    Direction.INBOUND,
                    Action.ALLOW,
                    Protocol.TCP,
                    "10.20.0.0/24",
                    "10.20.0.10/32",
                    22,
                    "sshd",
                    10,
                    LogLevel.ALL,
                    "Administrative SSH from management network"
            ));

            service.registerRule(rule(
                    "DENY-INBOUND-APP",
                    Direction.INBOUND,
                    Action.DENY,
                    Protocol.TCP,
                    "0.0.0.0/0",
                    "0.0.0.0/0",
                    8080,
                    "*",
                    20,
                    LogLevel.DENIED,
                    "Unapproved inbound application service"
            ));

            service.registerRule(rule(
                    "ALLOW-DNS",
                    Direction.OUTBOUND,
                    Action.ALLOW,
                    Protocol.UDP,
                    "10.20.0.10/32",
                    "10.20.0.53/32",
                    53,
                    "resolver",
                    30,
                    LogLevel.ALL,
                    "Approved DNS resolver"
            ));

            service.registerRule(rule(
                    "ALLOW-HTTPS",
                    Direction.OUTBOUND,
                    Action.ALLOW,
                    Protocol.TCP,
                    "10.20.0.10/32",
                    "0.0.0.0/0",
                    443,
                    "browser",
                    40,
                    LogLevel.ALL,
                    "Approved browser HTTPS"
            ));

            service.registerRule(rule(
                    "DENY-UNKNOWN-OUTBOUND",
                    Direction.OUTBOUND,
                    Action.DENY,
                    Protocol.ANY,
                    "0.0.0.0/0",
                    "0.0.0.0/0",
                    null,
                    "*",
                    90,
                    LogLevel.DENIED,
                    "Outbound traffic without explicit allow"
            ));

            List<Connection> requests = List.of(
                    new Connection(
                            Direction.INBOUND,
                            Protocol.TCP,
                            "10.20.0.15",
                            "10.20.0.10",
                            51000,
                            22,
                            "sshd",
                            "administrator"
                    ),
                    new Connection(
                            Direction.INBOUND,
                            Protocol.TCP,
                            "203.0.113.50",
                            "10.20.0.10",
                            51001,
                            8080,
                            "unknown",
                            null
                    ),
                    new Connection(
                            Direction.OUTBOUND,
                            Protocol.UDP,
                            "10.20.0.10",
                            "10.20.0.53",
                            53000,
                            53,
                            "resolver",
                            null
                    ),
                    new Connection(
                            Direction.OUTBOUND,
                            Protocol.TCP,
                            "10.20.0.10",
                            "198.51.100.20",
                            52000,
                            443,
                            "browser",
                            null
                    ),
                    new Connection(
                            Direction.OUTBOUND,
                            Protocol.TCP,
                            "10.20.0.10",
                            "198.51.100.40",
                            52001,
                            22,
                            "unknown",
                            null
                    )
            );

            for (Connection request : requests) {
                try {
                    Decision decision = service.evaluate(request);
                    System.out.printf(
                            "%-9s %-14s %-6s rule=%-24s %s%n",
                            request.direction(),
                            request.application(),
                            decision.action(),
                            decision.ruleId(),
                            decision.reason()
                    );
                } catch (PolicyViolationException | IllegalArgumentException error) {
                    System.out.println("Request rejected: " + error.getMessage());
                }
            }

            try {
                service.evaluate(new Connection(
                        Direction.OUTBOUND,
                        Protocol.TCP,
                        "invalid",
                        "198.51.100.10",
                        50000,
                        443,
                        "browser",
                        null
                ));
            } catch (IllegalArgumentException error) {
                System.out.println("Validation failure handled: " + error.getMessage());
            }

            System.out.println("\nAudit events:");
            service.auditEvents().forEach(event ->
                    System.out.printf(
                            "%s action=%s rule=%s application=%s reason=%s%n",
                            event.timestamp(),
                            event.action(),
                            event.ruleId(),
                            event.application(),
                            event.reason()
                    )
            );

        } catch (Exception error) {
            System.err.println("Fatal error: " + error.getMessage());
            System.exit(1);
        }
    }
}
