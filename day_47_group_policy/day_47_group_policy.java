import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/*
 * Enterprise repository for Group Policy definitions and effective-policy
 * evaluation. Designed for Java 17+, with no external dependencies.
 *
 * Compile: javac GroupPolicyEnterprise.java
 * Run:     java GroupPolicyEnterprise
 *
 * This models selected policy semantics for training and governance analysis.
 * It does not replace Windows Group Policy processing or security validation.
 */
public class GroupPolicyEnterprise {

    enum Category {
        SECURITY,
        PASSWORD,
        WORKSTATION
    }

    enum ScopeType {
        SITE,
        DOMAIN,
        OU
    }

    enum LinkMode {
        NORMAL,
        ENFORCED
    }

    record PolicySetting(String name, Object value, Category category) {
        PolicySetting {
            Objects.requireNonNull(name, "Setting name is required");
            Objects.requireNonNull(category, "Category is required");

            if (name.isBlank()) {
                throw new IllegalArgumentException(
                    "Setting name cannot be blank."
                );
            }

            if (name.equals("minimumPasswordLength")) {
                requireIntegerRange(value, 8, 128, name);
                requireCategory(category, Category.PASSWORD, name);
            } else if (name.equals("passwordHistoryCount")) {
                requireIntegerRange(value, 0, 50, name);
                requireCategory(category, Category.PASSWORD, name);
            } else if (name.equals("maximumPasswordAgeDays")) {
                requireIntegerRange(value, 0, 365, name);
                requireCategory(category, Category.PASSWORD, name);
            } else if (name.equals("minimumPasswordAgeDays")) {
                requireIntegerRange(value, 0, 365, name);
                requireCategory(category, Category.PASSWORD, name);
            } else if (name.equals("lockoutThreshold")) {
                requireIntegerRange(value, 0, 999, name);
            } else if (name.equals("screenLockTimeoutMinutes")) {
                requireIntegerRange(value, 1, 1440, name);
                requireCategory(category, Category.WORKSTATION, name);
            } else if (Set.of(
                "firewallEnabled",
                "usbStorageBlocked",
                "screenLockEnabled",
                "localAdminInstallationBlocked",
                "interactiveLogonBannerEnabled",
                "complexityEnabled"
            ).contains(name)) {
                if (!(value instanceof Boolean)) {
                    throw new IllegalArgumentException(
                        name + " must be Boolean."
                    );
                }
            }

            if (Set.of(
                "minimumPasswordLength",
                "passwordHistoryCount",
                "maximumPasswordAgeDays",
                "minimumPasswordAgeDays",
                "complexityEnabled"
            ).contains(name)) {
                requireCategory(category, Category.PASSWORD, name);
            }
        }

        private static void requireIntegerRange(
            Object value,
            int minimum,
            int maximum,
            String name
        ) {
            if (!(value instanceof Integer integer) ||
                integer < minimum ||
                integer > maximum) {
                throw new IllegalArgumentException(
                    name + " must be an integer from " +
                    minimum + " through " + maximum + "."
                );
            }
        }

        private static void requireCategory(
            Category actual,
            Category expected,
            String name
        ) {
            if (actual != expected) {
                throw new IllegalArgumentException(
                    name + " belongs to " + expected + "."
                );
            }
        }
    }

    static final class GroupPolicyObject {
        private final String name;
        private final String description;
        private final Map<String, PolicySetting> settings =
            new LinkedHashMap<>();
        private boolean enabled = true;

        GroupPolicyObject(String name, String description) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("GPO name is required.");
            }
            this.name = name;
            this.description = Objects.requireNonNull(description);
        }

        void put(PolicySetting setting) {
            settings.put(setting.name(), setting);
        }

        void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        String name() {
            return name;
        }

        boolean enabled() {
            return enabled;
        }

        String description() {
            return description;
        }

        Map<String, PolicySetting> settings() {
            return Collections.unmodifiableMap(settings);
        }
    }

    record PolicyLink(
        String gpoName,
        ScopeType scopeType,
        String scopeName,
        int linkOrder,
        LinkMode mode,
        boolean enabled
    ) {
        PolicyLink {
            Objects.requireNonNull(gpoName);
            Objects.requireNonNull(scopeType);
            Objects.requireNonNull(scopeName);
            Objects.requireNonNull(mode);

            if (gpoName.isBlank() || scopeName.isBlank()) {
                throw new IllegalArgumentException(
                    "GPO and scope names are required."
                );
            }
            if (linkOrder < 1) {
                throw new IllegalArgumentException(
                    "Link order must be positive."
                );
            }
        }
    }

    record Workstation(
        String hostname,
        String site,
        String domain,
        List<String> organizationalUnits
    ) {
        Workstation {
            if (hostname == null || hostname.isBlank()) {
                throw new IllegalArgumentException("Hostname is required.");
            }
            Objects.requireNonNull(site);
            Objects.requireNonNull(domain);
            organizationalUnits = List.copyOf(organizationalUnits);
        }
    }

    record PolicyEvaluation(
        Map<String, Object> effectiveSettings,
        Map<String, String> settingSources,
        List<String> appliedGpos,
        List<String> findings
    ) {
        PolicyEvaluation {
            effectiveSettings = Map.copyOf(effectiveSettings);
            settingSources = Map.copyOf(settingSources);
            appliedGpos = List.copyOf(appliedGpos);
            findings = List.copyOf(findings);
        }
    }

    static final class PolicyCatalog {
        private final Map<String, GroupPolicyObject> gpos =
            new LinkedHashMap<>();
        private final List<PolicyLink> links = new ArrayList<>();

        void register(GroupPolicyObject gpo) {
            if (gpos.putIfAbsent(gpo.name(), gpo) != null) {
                throw new IllegalArgumentException(
                    "Duplicate GPO: " + gpo.name()
                );
            }
        }

        void link(PolicyLink link) {
            if (!gpos.containsKey(link.gpoName())) {
                throw new IllegalArgumentException(
                    "Unknown GPO: " + link.gpoName()
                );
            }
            links.add(link);
        }

        PolicyEvaluation evaluate(Workstation machine) {
            List<PolicyLink> matching = links.stream()
                .filter(PolicyLink::enabled)
                .filter(link -> {
                    GroupPolicyObject gpo = gpos.get(link.gpoName());
                    return gpo != null && gpo.enabled();
                })
                .filter(link -> switch (link.scopeType()) {
                    case SITE -> link.scopeName().equals(machine.site());
                    case DOMAIN -> link.scopeName().equals(machine.domain());
                    case OU -> machine.organizationalUnits()
                        .contains(link.scopeName());
                })
                .sorted((left, right) -> {
                    int depth = Integer.compare(
                        scopeDepth(left.scopeType()),
                        scopeDepth(right.scopeType())
                    );
                    if (depth != 0) return depth;

                    int order = Integer.compare(
                        left.linkOrder(),
                        right.linkOrder()
                    );
                    if (order != 0) return order;

                    return left.gpoName().compareTo(right.gpoName());
                })
                .toList();

            Map<String, Object> effective = new HashMap<>();
            Map<String, String> sources = new HashMap<>();
            Set<String> enforcedSettings = new java.util.HashSet<>();
            List<String> applied = new ArrayList<>();

            for (PolicyLink link : matching) {
                GroupPolicyObject gpo = gpos.get(link.gpoName());
                applied.add(gpo.name());

                for (PolicySetting setting : gpo.settings().values()) {
                    String name = setting.name();

                    if (link.mode() == LinkMode.ENFORCED) {
                        effective.put(name, setting.value());
                        sources.put(name, gpo.name());
                        enforcedSettings.add(name);
                    } else if (!enforcedSettings.contains(name)) {
                        // Only settings, not entire GPOs, are protected by
                        // this simplified enforced-precedence representation.
                        effective.put(name, setting.value());
                        sources.put(name, gpo.name());
                    }
                }
            }

            List<String> findings = new ArrayList<>();
            if (Boolean.FALSE.equals(effective.get("firewallEnabled"))) {
                findings.add("Host firewall is disabled.");
            }
            if (Boolean.FALSE.equals(effective.get("screenLockEnabled"))) {
                findings.add("Automatic screen locking is disabled.");
            }

            int minimumAge = integerSetting(
                effective, "minimumPasswordAgeDays", 0
            );
            int maximumAge = integerSetting(
                effective, "maximumPasswordAgeDays", 0
            );
            if (maximumAge != 0 && minimumAge > maximumAge) {
                findings.add("Password age settings are inconsistent.");
            }

            if (integerSetting(effective, "lockoutThreshold", 10) == 0) {
                findings.add("Account lockout may be disabled.");
            }

            return new PolicyEvaluation(
                effective, sources, applied, findings
            );
        }

        private static int scopeDepth(ScopeType type) {
            return switch (type) {
                case SITE -> 0;
                case DOMAIN -> 1;
                case OU -> 2;
            };
        }

        private static int integerSetting(
            Map<String, Object> settings,
            String key,
            int fallback
        ) {
            Object value = settings.get(key);
            return value instanceof Integer integer ? integer : fallback;
        }
    }

    static GroupPolicyObject baseline() {
        GroupPolicyObject gpo = new GroupPolicyObject(
            "Domain-Security-Baseline",
            "Organization-wide account and endpoint safeguards."
        );
        gpo.put(new PolicySetting(
            "firewallEnabled", true, Category.WORKSTATION
        ));
        gpo.put(new PolicySetting(
            "interactiveLogonBannerEnabled", true, Category.SECURITY
        ));
        gpo.put(new PolicySetting(
            "minimumPasswordLength", 14, Category.PASSWORD
        ));
        gpo.put(new PolicySetting(
            "passwordHistoryCount", 24, Category.PASSWORD
        ));
        gpo.put(new PolicySetting(
            "maximumPasswordAgeDays", 0, Category.PASSWORD
        ));
        gpo.put(new PolicySetting(
            "minimumPasswordAgeDays", 1, Category.PASSWORD
        ));
        gpo.put(new PolicySetting(
            "complexityEnabled", true, Category.PASSWORD
        ));
        gpo.put(new PolicySetting(
            "lockoutThreshold", 10, Category.SECURITY
        ));
        return gpo;
    }

    static GroupPolicyObject engineeringPolicy() {
        GroupPolicyObject gpo = new GroupPolicyObject(
            "Engineering-Workstations",
            "Controls for managed engineering endpoints."
        );
        gpo.put(new PolicySetting(
            "usbStorageBlocked", true, Category.WORKSTATION
        ));
        gpo.put(new PolicySetting(
            "screenLockEnabled", true, Category.WORKSTATION
        ));
        gpo.put(new PolicySetting(
            "screenLockTimeoutMinutes", 10, Category.WORKSTATION
        ));
        gpo.put(new PolicySetting(
            "localAdminInstallationBlocked", true, Category.WORKSTATION
        ));
        return gpo;
    }

    static GroupPolicyObject legacyException() {
        GroupPolicyObject gpo = new GroupPolicyObject(
            "Legacy-Firewall-Exception",
            "An intentionally conflicting OU setting."
        );
        gpo.put(new PolicySetting(
            "firewallEnabled", false, Category.WORKSTATION
        ));
        return gpo;
    }

    public static void main(String[] args) {
        PolicyCatalog catalog = new PolicyCatalog();

        catalog.register(baseline());
        catalog.register(engineeringPolicy());
        catalog.register(legacyException());

        catalog.link(new PolicyLink(
            "Domain-Security-Baseline",
            ScopeType.DOMAIN,
            "corp.example",
            1,
            LinkMode.ENFORCED,
            true
        ));
        catalog.link(new PolicyLink(
            "Engineering-Workstations",
            ScopeType.OU,
            "Engineering",
            1,
            LinkMode.NORMAL,
            true
        ));
        catalog.link(new PolicyLink(
            "Legacy-Firewall-Exception",
            ScopeType.OU,
            "Engineering",
            2,
            LinkMode.NORMAL,
            true
        ));

        Workstation machine = new Workstation(
            "ENG-WS-042",
            "North-Office",
            "corp.example",
            List.of("Engineering")
        );

        PolicyEvaluation evaluation = catalog.evaluate(machine);

        System.out.println("Effective settings for " + machine.hostname());
        new TreeMap<>(evaluation.effectiveSettings()).forEach(
            (name, value) -> System.out.println(
                name + " = " + value +
                " [source: " + evaluation.settingSources().get(name) + "]"
            )
        );

        System.out.println("\nApplied GPOs: " + evaluation.appliedGpos());
        System.out.println("Findings: " + evaluation.findings());

        if (!Boolean.TRUE.equals(
            evaluation.effectiveSettings().get("firewallEnabled")
        )) {
            throw new IllegalStateException(
                "Enforced domain firewall policy was not preserved."
            );
        }

        if (!Boolean.TRUE.equals(
            evaluation.effectiveSettings().get("usbStorageBlocked")
        )) {
            throw new IllegalStateException(
                "Engineering storage restriction was not applied."
            );
        }

        try {
            new PolicySetting(
                "minimumPasswordLength", 4, Category.PASSWORD
            );
            throw new AssertionError("Invalid password policy was accepted.");
        } catch (IllegalArgumentException expected) {
            System.out.println(
                "Invalid policy rejected: " + expected.getMessage()
            );
        }

        System.out.println("Governance checks passed.");
    }
}
