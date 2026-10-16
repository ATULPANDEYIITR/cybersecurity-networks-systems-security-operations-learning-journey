import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/*
 * Enterprise directory architecture and governance model.
 *
 * Save as DirectoryArchitecture.java
 * Compile: javac DirectoryArchitecture.java
 * Run: java DirectoryArchitecture
 *
 * This program models AD DS concepts without connecting to a Windows domain.
 */
public class DirectoryArchitecture {

    enum ObjectType {
        USER, GROUP, COMPUTER, ORGANIZATIONAL_UNIT
    }

    enum TrustDirection {
        OUTBOUND, INBOUND, BIDIRECTIONAL
    }

    enum TrustScope {
        DOMAIN, FOREST, EXTERNAL
    }

    enum ServiceState {
        HEALTHY, DNS_FAILURE, CONTROLLER_UNAVAILABLE, LDAP_FAILURE
    }

    static final class DirectoryException extends RuntimeException {
        DirectoryException(String message) {
            super(message);
        }
    }

    static String dnsName(String value) {
        if (value == null) {
            throw new DirectoryException("DNS name cannot be null.");
        }

        String name = value.trim().replaceAll("\\.+$", "")
                .toLowerCase(Locale.ROOT);

        if (name.isEmpty() || name.length() > 253) {
            throw new DirectoryException("Invalid DNS name length.");
        }

        for (String label : name.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63
                    || !Pattern.matches(
                    "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)) {
                throw new DirectoryException(
                        "Invalid DNS label: " + label);
            }
        }

        return name;
    }

    record DistinguishedName(String value) {
        DistinguishedName {
            Objects.requireNonNull(value, "DN cannot be null");
            if (value.isBlank()
                    || !value.matches("(?i)^(CN|OU|DC)=.+")) {
                throw new DirectoryException(
                        "Invalid distinguished name: " + value);
            }
        }

        String normalized() {
            return value.toLowerCase(Locale.ROOT);
        }
    }

    record DirectoryEntry(
            DistinguishedName dn,
            ObjectType type,
            Map<String, String> attributes) {

        DirectoryEntry {
            Objects.requireNonNull(dn);
            Objects.requireNonNull(type);
            Map<String, String> normalized = new TreeMap<>();
            attributes.forEach((key, value) -> normalized.put(
                    key.toLowerCase(Locale.ROOT), value));
            attributes = Collections.unmodifiableMap(normalized);
        }

        String attribute(String name) {
            return attributes.get(name.toLowerCase(Locale.ROOT));
        }
    }

    static final class Domain {
        private final String name;
        private final String forestRoot;
        private final String parent;
        private final Map<String, DirectoryEntry> entries =
                new LinkedHashMap<>();

        Domain(String name, String forestRoot, String parent) {
            this.name = dnsName(name);
            this.forestRoot = dnsName(forestRoot);
            this.parent = parent == null ? null : dnsName(parent);
        }

        String name() {
            return name;
        }

        String forestRoot() {
            return forestRoot;
        }

        String parent() {
            return parent;
        }

        String baseDn() {
            List<String> components = new ArrayList<>();
            for (String label : name.split("\\.")) {
                components.add("DC=" + label);
            }
            return String.join(",", components);
        }

        void addEntry(DirectoryEntry entry) {
            String key = entry.dn().normalized();
            if (entries.putIfAbsent(key, entry) != null) {
                throw new DirectoryException(
                        "Duplicate distinguished name: " + entry.dn());
            }
        }

        List<DirectoryEntry> search(
                ObjectType type, String attribute, String expectedValue) {

            List<DirectoryEntry> matches = new ArrayList<>();

            for (DirectoryEntry entry : entries.values()) {
                if (entry.type() != type) {
                    continue;
                }

                String actual = entry.attribute(attribute);
                if (actual != null && actual.equalsIgnoreCase(expectedValue)) {
                    matches.add(entry);
                }
            }

            return List.copyOf(matches);
        }
    }

    static final class Forest {
        private final String rootDomain;
        private final Map<String, Domain> domains = new TreeMap<>();

        Forest(String rootDomain) {
            this.rootDomain = dnsName(rootDomain);
        }

        String rootDomain() {
            return rootDomain;
        }

        void addDomain(Domain domain) {
            if (!domain.forestRoot().equals(rootDomain)) {
                throw new DirectoryException(
                        "Domain is assigned to a different forest.");
            }

            if (domains.isEmpty()) {
                if (!domain.name().equals(rootDomain)
                        || domain.parent() != null) {
                    throw new DirectoryException(
                            "The first domain must be the forest root.");
                }
            } else {
                Domain parent = domains.get(domain.parent());
                if (parent == null
                        || !domain.name().endsWith("." + parent.name())) {
                    throw new DirectoryException(
                            "Invalid child-domain hierarchy.");
                }
            }

            if (domains.putIfAbsent(domain.name(), domain) != null) {
                throw new DirectoryException(
                        "Domain already exists: " + domain.name());
            }
        }

        Domain requireDomain(String name) {
            Domain domain = domains.get(dnsName(name));
            if (domain == null) {
                throw new DirectoryException(
                        "Domain not found: " + name);
            }
            return domain;
        }

        boolean contains(String name) {
            return domains.containsKey(dnsName(name));
        }
    }

    record Trust(
            String sourceForest,
            String targetForest,
            TrustDirection direction,
            TrustScope scope,
            boolean transitive,
            boolean enabled) {

        Trust {
            sourceForest = dnsName(sourceForest);
            targetForest = dnsName(targetForest);
            Objects.requireNonNull(direction);
            Objects.requireNonNull(scope);

            if (sourceForest.equals(targetForest)) {
                throw new DirectoryException(
                        "Self-trust is not permitted.");
            }
        }
    }

    record SrvRecord(
            String queryName,
            String target,
            int port,
            int priority,
            int weight) {

        SrvRecord {
            queryName = dnsName(queryName);
            target = dnsName(target);

            if (port < 1 || port > 65535 || priority < 0 || weight < 0) {
                throw new DirectoryException("Invalid SRV record values.");
            }
        }
    }

    static final class DnsService {
        private final Map<String, List<SrvRecord>> records =
                new HashMap<>();

        void register(SrvRecord record) {
            records.computeIfAbsent(record.queryName(),
                    ignored -> new ArrayList<>()).add(record);
        }

        List<SrvRecord> locate(String queryName) {
            List<SrvRecord> result = new ArrayList<>(
                    records.getOrDefault(dnsName(queryName), List.of()));

            result.sort((left, right) -> {
                int priorityOrder = Integer.compare(
                        left.priority(), right.priority());
                if (priorityOrder != 0) {
                    return priorityOrder;
                }
                return Integer.compare(right.weight(), left.weight());
            });

            return List.copyOf(result);
        }
    }

    static final class TrustService {
        private final List<Trust> trusts = new ArrayList<>();

        void register(Trust trust) {
            boolean duplicate = trusts.stream().anyMatch(existing ->
                    existing.sourceForest().equals(trust.sourceForest())
                            && existing.targetForest().equals(
                            trust.targetForest())
                            && existing.scope() == trust.scope());

            if (duplicate) {
                throw new DirectoryException("Duplicate trust.");
            }

            trusts.add(trust);
        }

        boolean permitsReachability(String source, String target) {
            String from = dnsName(source);
            String to = dnsName(target);
            if (from.equals(to)) return true;

            Map<String, Set<String>> graph = new HashMap<>();

            for (Trust trust : trusts) {
                if (!trust.enabled() || trust.scope() != TrustScope.FOREST) {
                    continue;
                }

                if (trust.direction() == TrustDirection.OUTBOUND
                        || trust.direction() == TrustDirection.BIDIRECTIONAL) {
                    graph.computeIfAbsent(trust.sourceForest(),
                            ignored -> new HashSet<>())
                            .add(trust.targetForest());
                }

                if (trust.direction() == TrustDirection.INBOUND
                        || trust.direction() == TrustDirection.BIDIRECTIONAL) {
                    graph.computeIfAbsent(trust.targetForest(),
                            ignored -> new HashSet<>())
                            .add(trust.sourceForest());
                }
            }

            Set<String> visited = new HashSet<>();
            ArrayDeque<String> queue = new ArrayDeque<>();
            queue.add(from);
            visited.add(from);

            while (!queue.isEmpty()) {
                String current = queue.removeFirst();

                for (String next : graph.getOrDefault(current, Set.of())) {
                    if (next.equals(to)) return true;
                    if (visited.add(next)) queue.addLast(next);
                }
            }

            return false;
        }
    }

    static final class DirectoryService {
        private final Map<String, Forest> forests = new TreeMap<>();
        private final DnsService dns = new DnsService();
        private final TrustService trusts = new TrustService();

        void registerForest(Forest forest) {
            if (forests.putIfAbsent(forest.rootDomain(), forest) != null) {
                throw new DirectoryException("Duplicate forest.");
            }
        }

        DnsService dns() {
            return dns;
        }

        TrustService trusts() {
            return trusts;
        }

        Domain requireDomain(String name) {
            String normalized = dnsName(name);

            for (Forest forest : forests.values()) {
                if (forest.contains(normalized)) {
                    return forest.requireDomain(normalized);
                }
            }

            throw new DirectoryException(
                    "Domain is not registered: " + normalized);
        }

        boolean sameForest(String firstDomain, String secondDomain) {
            Domain first = requireDomain(firstDomain);
            Domain second = requireDomain(secondDomain);
            return first.forestRoot().equals(second.forestRoot());
        }

        boolean canAttemptCrossForestAccess(
                String sourceDomain, String targetDomain) {
            Domain source = requireDomain(sourceDomain);
            Domain target = requireDomain(targetDomain);

            if (source.forestRoot().equals(target.forestRoot())) {
                return true;
            }

            return trusts.permitsReachability(
                    source.forestRoot(), target.forestRoot());
        }

        List<SrvRecord> discoverLdap(String domain) {
            String query = "_ldap._tcp." + dnsName(domain);
            List<SrvRecord> results = dns.locate(query);

            if (results.isEmpty()) {
                throw new DirectoryException(
                        "No LDAP service records for " + query);
            }

            return results;
        }

        List<DirectoryEntry> searchUsers(
                String domainName, String department) {
            Domain domain = requireDomain(domainName);

            // DNS service discovery is checked before a query is considered
            // operationally possible. It does not guarantee LDAP bind success.
            discoverLdap(domainName);

            return domain.search(
                    ObjectType.USER, "department", department);
        }
    }

    static DirectoryService createEnvironment() {
        DirectoryService service = new DirectoryService();

        Forest corporate = new Forest("corp.example.com");
        Domain root = new Domain(
                "corp.example.com", "corp.example.com", null);
        root.addEntry(new DirectoryEntry(
                new DistinguishedName(
                        "OU=ServiceAccounts,DC=corp,DC=example,DC=com"),
                ObjectType.ORGANIZATIONAL_UNIT,
                Map.of("ou", "ServiceAccounts")));

        Domain engineering = new Domain(
                "engineering.corp.example.com",
                "corp.example.com",
                "corp.example.com");

        engineering.addEntry(new DirectoryEntry(
                new DistinguishedName(
                        "CN=Riya Sharma,OU=Engineering,"
                                + "DC=engineering,DC=corp,DC=example,DC=com"),
                ObjectType.USER,
                Map.of(
                        "cn", "Riya Sharma",
                        "sAMAccountName", "riya.sharma",
                        "department", "Engineering",
                        "mail", "riya.sharma@corp.example.com")));

        engineering.addEntry(new DirectoryEntry(
                new DistinguishedName(
                        "CN=Build Agent,OU=Computers,"
                                + "DC=engineering,DC=corp,DC=example,DC=com"),
                ObjectType.COMPUTER,
                Map.of(
                        "cn", "Build Agent",
                        "dNSHostName",
                        "build01.engineering.corp.example.com")));

        corporate.addDomain(root);
        corporate.addDomain(engineering);
        service.registerForest(corporate);

        Forest partner = new Forest("partner.example.net");
        partner.addDomain(new Domain(
                "partner.example.net", "partner.example.net", null));
        service.registerForest(partner);

        service.trusts().register(new Trust(
                "corp.example.com",
                "partner.example.net",
                TrustDirection.BIDIRECTIONAL,
                TrustScope.FOREST,
                true,
                true));

        service.dns().register(new SrvRecord(
                "_ldap._tcp.engineering.corp.example.com",
                "dc01.corp.example.com", 389, 0, 100));

        service.dns().register(new SrvRecord(
                "_kerberos._tcp.engineering.corp.example.com",
                "dc01.corp.example.com", 88, 0, 100));

        return service;
    }

    public static void main(String[] args) {
        DirectoryService service = createEnvironment();

        System.out.println("=== LDAP Service Discovery ===");
        for (SrvRecord record :
                service.discoverLdap("engineering.corp.example.com")) {
            System.out.printf(
                    "%s:%d priority=%d weight=%d%n",
                    record.target(), record.port(),
                    record.priority(), record.weight());
        }

        System.out.println("\n=== Directory Search ===");
        List<DirectoryEntry> users = service.searchUsers(
                "engineering.corp.example.com", "Engineering");

        for (DirectoryEntry user : users) {
            System.out.println("DN: " + user.dn().value());
            System.out.println("Account: "
                    + user.attribute("sAMAccountName"));
        }

        System.out.println("\n=== Trust Evaluation ===");
        System.out.println("Same forest: " + service.sameForest(
                "corp.example.com",
                "engineering.corp.example.com"));

        System.out.println("Cross-forest reachability: "
                + service.canAttemptCrossForestAccess(
                "engineering.corp.example.com",
                "partner.example.net"));

        System.out.println("\n=== Failure Handling ===");
        try {
            service.discoverLdap("unknown.example.org");
        } catch (DirectoryException exception) {
            System.out.println("Discovery failure: " + exception.getMessage());
        }

        try {
            service.requireDomain("unknown.example.org");
        } catch (DirectoryException exception) {
            System.out.println("Lookup failure: " + exception.getMessage());
        }
    }
}
