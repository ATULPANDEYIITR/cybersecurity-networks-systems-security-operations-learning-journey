import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Enterprise Windows networking governance model.
 *
 * Compile: javac WindowsNetworking.java
 * Run:     java WindowsNetworking
 *
 * This program evaluates declared dependencies and firewall policy.
 * It does not change host configuration or contact remote systems.
 */
public class WindowsNetworking {

    enum NetworkService {
        SMB("Windows file sharing", Set.of(445)),
        RDP("Remote desktop sessions", Set.of(3389)),
        WINRM("Windows remote management", Set.of(5985, 5986)),
        RPC("RPC endpoint discovery", Set.of(135));

        private final String purpose;
        private final Set<Integer> ports;

        NetworkService(String purpose, Set<Integer> ports) {
            this.purpose = purpose;
            this.ports = Set.copyOf(ports);
        }

        public String purpose() {
            return purpose;
        }

        public Set<Integer> ports() {
            return ports;
        }
    }

    enum FirewallProfile {
        DOMAIN,
        PRIVATE,
        PUBLIC
    }

    enum RuleAction {
        ALLOW,
        BLOCK
    }

    enum AssetState {
        ACTIVE,
        UNDER_REVIEW,
        RETIRED
    }

    record NetworkAsset(
        String hostname,
        String businessOwner,
        FirewallProfile expectedProfile,
        Set<NetworkService> requiredServices,
        AssetState state
    ) {
        NetworkAsset {
            if (hostname == null || hostname.isBlank()) {
                throw new IllegalArgumentException("Hostname is required.");
            }
            if (businessOwner == null || businessOwner.isBlank()) {
                throw new IllegalArgumentException("Business owner is required.");
            }

            Objects.requireNonNull(expectedProfile);
            Objects.requireNonNull(requiredServices);
            Objects.requireNonNull(state);
            requiredServices = Set.copyOf(requiredServices);
        }
    }

    record FirewallRule(
        String name,
        NetworkService service,
        int port,
        FirewallProfile profile,
        RuleAction action,
        Optional<String> allowedSource
    ) {
        FirewallRule {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("Rule name is required.");
            }
            Objects.requireNonNull(service);
            Objects.requireNonNull(profile);
            Objects.requireNonNull(action);
            Objects.requireNonNull(allowedSource);

            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Invalid port: " + port);
            }
            if (!service.ports().contains(port)) {
                throw new IllegalArgumentException(
                    "Port " + port + " is not a standard endpoint for " + service
                );
            }
            allowedSource.ifPresent(source -> {
                if (source.isBlank()) {
                    throw new IllegalArgumentException("Source cannot be blank.");
                }
            });
        }
    }

    record Assessment(
        String hostname,
        NetworkService service,
        int port,
        boolean required,
        RuleAction decision,
        String reason
    ) {}

    static final class FirewallPolicy {
        private final RuleAction defaultInbound;
        private final List<FirewallRule> rules = new ArrayList<>();

        FirewallPolicy(RuleAction defaultInbound) {
            this.defaultInbound = Objects.requireNonNull(defaultInbound);
        }

        void addRule(FirewallRule rule) {
            Objects.requireNonNull(rule);
            rules.add(rule);
        }

        RuleAction evaluate(
            NetworkService service,
            int port,
            FirewallProfile profile,
            String source
        ) {
            Objects.requireNonNull(service);
            Objects.requireNonNull(profile);

            if (!service.ports().contains(port)) {
                throw new IllegalArgumentException(
                    "Unsupported standard port for " + service + ": " + port
                );
            }

            // The model uses explicit first-match behavior for teaching.
            // Windows Firewall's actual rule resolution is more complex.
            for (FirewallRule rule : rules) {
                if (rule.service() != service ||
                    rule.port() != port ||
                    rule.profile() != profile) {
                    continue;
                }

                if (rule.allowedSource().isPresent() &&
                    !rule.allowedSource().get().equals(source)) {
                    continue;
                }

                return rule.action();
            }

            return defaultInbound;
        }
    }

    static final class NetworkGovernanceService {
        private final Map<String, NetworkAsset> inventory = new HashMap<>();
        private final FirewallPolicy policy;

        NetworkGovernanceService(FirewallPolicy policy) {
            this.policy = Objects.requireNonNull(policy);
        }

        void register(NetworkAsset asset) {
            Objects.requireNonNull(asset);
            String key = asset.hostname().toLowerCase();

            if (inventory.putIfAbsent(key, asset) != null) {
                throw new IllegalStateException(
                    "Asset already registered: " + asset.hostname()
                );
            }
        }

        List<Assessment> assess(
            String hostname,
            FirewallProfile observedProfile,
            String source
        ) {
            NetworkAsset asset = inventory.get(hostname.toLowerCase());

            if (asset == null) {
                throw new IllegalArgumentException(
                    "No inventory record for " + hostname
                );
            }
            if (asset.state() == AssetState.RETIRED) {
                throw new IllegalStateException(
                    "Retired asset cannot receive an active assessment."
                );
            }

            List<Assessment> assessments = new ArrayList<>();

            for (NetworkService service : NetworkService.values()) {
                boolean required = asset.requiredServices().contains(service);

                for (int port : service.ports().stream().sorted().toList()) {
                    RuleAction decision = policy.evaluate(
                        service, port, observedProfile, source
                    );

                    String reason;
                    if (required && decision == RuleAction.BLOCK) {
                        reason = "Required dependency is blocked.";
                    } else if (!required && decision == RuleAction.ALLOW) {
                        reason = "Unrequired service is permitted; review exposure.";
                    } else if (service == NetworkService.RPC) {
                        reason =
                            "TCP 135 identifies the RPC endpoint mapper; "
                            + "dependent RPC endpoints require separate review.";
                    } else {
                        reason = "Decision matches the declared policy.";
                    }

                    assessments.add(new Assessment(
                        asset.hostname(), service, port, required, decision, reason
                    ));
                }
            }

            return List.copyOf(assessments);
        }
    }

    private static FirewallRule rule(
        String name,
        NetworkService service,
        int port,
        FirewallProfile profile,
        RuleAction action,
        String source
    ) {
        return new FirewallRule(
            name,
            service,
            port,
            profile,
            action,
            Optional.ofNullable(source)
        );
    }

    public static void main(String[] args) {
        FirewallPolicy policy = new FirewallPolicy(RuleAction.BLOCK);

        policy.addRule(rule(
            "Corporate SMB access",
            NetworkService.SMB,
            445,
            FirewallProfile.DOMAIN,
            RuleAction.ALLOW,
            "192.168.20.15"
        ));

        policy.addRule(rule(
            "Block public SMB",
            NetworkService.SMB,
            445,
            FirewallProfile.PUBLIC,
            RuleAction.BLOCK,
            null
        ));

        policy.addRule(rule(
            "Management gateway RDP",
            NetworkService.RDP,
            3389,
            FirewallProfile.DOMAIN,
            RuleAction.ALLOW,
            "192.168.20.15"
        ));

        policy.addRule(rule(
            "Management gateway WinRM HTTPS",
            NetworkService.WINRM,
            5986,
            FirewallProfile.DOMAIN,
            RuleAction.ALLOW,
            "192.168.20.15"
        ));

        NetworkGovernanceService governance =
            new NetworkGovernanceService(policy);

        governance.register(new NetworkAsset(
            "fileserver-02",
            "Infrastructure Operations",
            FirewallProfile.DOMAIN,
            EnumSet.of(NetworkService.SMB, NetworkService.RPC),
            AssetState.ACTIVE
        ));

        governance.register(new NetworkAsset(
            "admin-pc-02",
            "Endpoint Engineering",
            FirewallProfile.DOMAIN,
            EnumSet.of(
                NetworkService.RDP,
                NetworkService.WINRM,
                NetworkService.RPC
            ),
            AssetState.UNDER_REVIEW
        ));

        System.out.println("Assessment generated at " + Instant.now());

        List<Assessment> report = governance.assess(
            "fileserver-02",
            FirewallProfile.DOMAIN,
            "192.168.20.15"
        );

        for (Assessment item : report) {
            System.out.printf(
                "%s | %-5s | TCP %d | required=%-5s | %-5s | %s%n",
                item.hostname(),
                item.service(),
                item.port(),
                item.required(),
                item.decision(),
                item.reason()
            );
        }

        System.out.println("\nValidation and policy checks");

        try {
            policy.addRule(rule(
                "Invalid RDP mapping",
                NetworkService.RDP,
                445,
                FirewallProfile.DOMAIN,
                RuleAction.ALLOW,
                null
            ));
        } catch (IllegalArgumentException exception) {
            System.out.println("Rejected invalid rule: " + exception.getMessage());
        }

        try {
            governance.register(new NetworkAsset(
                "fileserver-02",
                "Another Owner",
                FirewallProfile.DOMAIN,
                Set.of(NetworkService.SMB),
                AssetState.ACTIVE
            ));
        } catch (IllegalStateException exception) {
            System.out.println("Rejected duplicate asset: " + exception.getMessage());
        }

        try {
            governance.assess(
                "unknown-host",
                FirewallProfile.PRIVATE,
                "192.168.20.15"
            );
        } catch (IllegalArgumentException exception) {
            System.out.println("Rejected unknown asset: " + exception.getMessage());
        }

        System.out.println(
            "\nA policy decision is not proof of live reachability, listener "
            + "health, authentication success, or protocol security."
        );
    }
}
