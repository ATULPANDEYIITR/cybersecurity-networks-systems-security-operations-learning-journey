import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Enterprise network segmentation governance.
 *
 * Demonstrates:
 * - VLAN and subnet inventory management
 * - Trust-zone isolation
 * - DMZ boundary controls
 * - Microsegmentation
 * - East-west traffic policies
 * - Policy revision approvals
 * - Separation of duties
 * - Explicit policy lifecycle transitions
 * - Centralized merge-free traffic evaluation
 *
 * Compile:
 *     javac NetworkSegmentationGovernance.java
 *
 * Run:
 *     java NetworkSegmentationGovernance
 */
public class NetworkSegmentationGovernance {

    enum Zone {
        USER,
        DMZ,
        APPLICATION,
        DATA,
        MANAGEMENT,
        INTERNET
    }

    enum Protocol {
        TCP,
        UDP
    }

    enum Action {
        ALLOW,
        DENY
    }

    enum ApprovalRole {
        NETWORK_SECURITY,
        PLATFORM_OPERATIONS
    }

    enum RevisionState {
        DRAFT,
        ACTIVE,
        RETIRED
    }

    enum TrafficClass {
        NORTH_SOUTH,
        EAST_WEST,
        INTRA_SEGMENT
    }

    static class DomainValidationException extends RuntimeException {
        DomainValidationException(String message) {
            super(message);
        }
    }

    static class PolicyTransitionException extends RuntimeException {
        PolicyTransitionException(String message) {
            super(message);
        }
    }

    record IPv4Range(long first, long last, int prefix) {

        static IPv4Range parse(String cidr) {
            String[] parts = cidr.split("/", -1);

            if (parts.length != 2) {
                throw new DomainValidationException(
                    "CIDR must contain an address and prefix."
                );
            }

            long address = parseAddress(parts[0]);
            int prefix;

            try {
                prefix = Integer.parseInt(parts[1]);
            } catch (NumberFormatException exception) {
                throw new DomainValidationException(
                    "Invalid CIDR prefix."
                );
            }

            if (prefix < 0 || prefix > 32) {
                throw new DomainValidationException(
                    "CIDR prefix must be between 0 and 32."
                );
            }

            long fullMask = 0xFFFF_FFFFL;

            long mask = prefix == 0
                ? 0L
                : (fullMask << (32 - prefix)) & fullMask;

            long first = address & mask;
            long last = first | (fullMask ^ mask);

            if (first != address) {
                throw new DomainValidationException(
                    "CIDR address contains host bits."
                );
            }

            return new IPv4Range(first, last, prefix);
        }

        static long parseAddress(String address) {
            String[] octets = address.split("\\.", -1);

            if (octets.length != 4) {
                throw new DomainValidationException(
                    "IPv4 address must contain four octets."
                );
            }

            long result = 0;

            for (String octet : octets) {
                if (!octet.matches("[0-9]{1,3}")) {
                    throw new DomainValidationException(
                        "Invalid IPv4 octet."
                    );
                }

                int value = Integer.parseInt(octet);

                if (value > 255) {
                    throw new DomainValidationException(
                        "IPv4 octet exceeds 255."
                    );
                }

                result = (result << 8) | value;
            }

            return result;
        }

        boolean contains(long address) {
            return address >= first && address <= last;
        }

        boolean overlaps(IPv4Range other) {
            return first <= other.last && other.first <= last;
        }
    }

    record Segment(
        String id,
        String name,
        int vlanId,
        String cidr,
        Zone zone
    ) {
        Segment {
            if (
                id == null || id.isBlank() ||
                name == null || name.isBlank() ||
                zone == null
            ) {
                throw new DomainValidationException(
                    "Segment identity and trust zone are required."
                );
            }

            if (vlanId < 1 || vlanId > 4094) {
                throw new DomainValidationException(
                    "VLAN ID must be between 1 and 4094."
                );
            }

            IPv4Range.parse(cidr);
        }

        IPv4Range range() {
            return IPv4Range.parse(cidr);
        }
    }

    record Endpoint(
        String id,
        String segmentId,
        String address,
        Map<String, String> labels
    ) {
        Endpoint {
            if (
                id == null || id.isBlank() ||
                segmentId == null || segmentId.isBlank()
            ) {
                throw new DomainValidationException(
                    "Endpoint identity and segment are required."
                );
            }

            IPv4Range.parseAddress(address);
            labels = Map.copyOf(labels);

            if (
                labels.get("role") == null ||
                labels.get("role").isBlank()
            ) {
                throw new DomainValidationException(
                    "Endpoint role label is required."
                );
            }
        }

        String role() {
            return labels.get("role");
        }
    }

    record NetworkRule(
        String id,
        int priority,
        Zone sourceZone,
        Zone destinationZone,
        Protocol protocol,
        int portFrom,
        int portTo,
        Action action
    ) {
        NetworkRule {
            validateRule(
                id,
                priority,
                protocol,
                portFrom,
                portTo,
                action
            );

            if (sourceZone == null || destinationZone == null) {
                throw new DomainValidationException(
                    "Network rule zones are required."
                );
            }
        }
    }

    record MicroRule(
        String id,
        int priority,
        String sourceRole,
        String destinationRole,
        Protocol protocol,
        int portFrom,
        int portTo,
        Action action
    ) {
        MicroRule {
            validateRule(
                id,
                priority,
                protocol,
                portFrom,
                portTo,
                action
            );

            if (
                sourceRole == null || sourceRole.isBlank() ||
                destinationRole == null || destinationRole.isBlank()
            ) {
                throw new DomainValidationException(
                    "Microsegmentation selectors are required."
                );
            }
        }
    }

    record TrafficFlow(
        String id,
        String sourceId,
        String destinationId,
        Protocol protocol,
        int destinationPort
    ) {
        TrafficFlow {
            if (
                id == null || id.isBlank() ||
                sourceId == null || sourceId.isBlank() ||
                destinationId == null || destinationId.isBlank()
            ) {
                throw new DomainValidationException(
                    "Traffic flow identifiers are required."
                );
            }

            if (
                protocol == null ||
                destinationPort < 1 ||
                destinationPort > 65535
            ) {
                throw new DomainValidationException(
                    "Invalid flow protocol or port."
                );
            }
        }
    }

    record Evaluation(
        String flowId,
        TrafficClass trafficClass,
        boolean allowed,
        String networkResult,
        String microResult,
        String reason
    ) {}

    static void validateRule(
        String id,
        int priority,
        Protocol protocol,
        int firstPort,
        int lastPort,
        Action action
    ) {
        if (id == null || id.isBlank()) {
            throw new DomainValidationException("Rule ID is required.");
        }

        if (priority < 0) {
            throw new DomainValidationException(
                "Rule priority cannot be negative."
            );
        }

        if (protocol == null || action == null) {
            throw new DomainValidationException(
                "Rule protocol and action are required."
            );
        }

        if (
            firstPort < 1 ||
            lastPort > 65535 ||
            firstPort > lastPort
        ) {
            throw new DomainValidationException(
                "Invalid rule port range."
            );
        }
    }

    static class NetworkInventory {

        private final Map<String, Segment> segments = new HashMap<>();
        private final Map<String, Endpoint> endpoints = new HashMap<>();
        private final Set<Integer> vlanIds = new HashSet<>();
        private final Set<String> endpointAddresses = new HashSet<>();

        void addSegment(Segment segment) {
            if (segments.containsKey(segment.id())) {
                throw new DomainValidationException(
                    "Duplicate segment ID."
                );
            }

            if (!vlanIds.add(segment.vlanId())) {
                throw new DomainValidationException(
                    "VLAN ID is already assigned."
                );
            }

            for (Segment existing : segments.values()) {
                if (segment.range().overlaps(existing.range())) {
                    vlanIds.remove(segment.vlanId());

                    throw new DomainValidationException(
                        "Overlapping IPv4 ranges are not permitted."
                    );
                }
            }

            segments.put(segment.id(), segment);
        }

        void addEndpoint(Endpoint endpoint) {
            if (endpoints.containsKey(endpoint.id())) {
                throw new DomainValidationException(
                    "Duplicate endpoint ID."
                );
            }

            Segment segment = getSegment(endpoint.segmentId());
            long address = IPv4Range.parseAddress(endpoint.address());

            if (!segment.range().contains(address)) {
                throw new DomainValidationException(
                    "Endpoint IP is outside its assigned network."
                );
            }

            if (!endpointAddresses.add(endpoint.address())) {
                throw new DomainValidationException(
                    "Duplicate endpoint IP."
                );
            }

            endpoints.put(endpoint.id(), endpoint);
        }

        Segment getSegment(String id) {
            Segment segment = segments.get(id);

            if (segment == null) {
                throw new DomainValidationException(
                    "Unknown segment: " + id
                );
            }

            return segment;
        }

        Endpoint getEndpoint(String id) {
            Endpoint endpoint = endpoints.get(id);

            if (endpoint == null) {
                throw new DomainValidationException(
                    "Unknown endpoint: " + id
                );
            }

            return endpoint;
        }

        int segmentCount() {
            return segments.size();
        }

        int endpointCount() {
            return endpoints.size();
        }
    }

    /**
     * A policy revision is a controlled governance object.
     * A draft needs approvals from both required organizational roles.
     * Its creator cannot approve their own revision.
     */
    static final class PolicyRevision {

        private final String revisionId;
        private final String policyName;
        private final int version;
        private final String createdBy;
        private final Set<ApprovalRole> requiredRoles;

        private final Map<String, ApprovalRole> approvals =
            new HashMap<>();

        private RevisionState state = RevisionState.DRAFT;

        PolicyRevision(
            String revisionId,
            String policyName,
            int version,
            String createdBy,
            Set<ApprovalRole> requiredRoles
        ) {
            if (
                revisionId == null || revisionId.isBlank() ||
                policyName == null || policyName.isBlank() ||
                createdBy == null || createdBy.isBlank() ||
                version < 1
            ) {
                throw new DomainValidationException(
                    "Invalid policy revision metadata."
                );
            }

            if (requiredRoles == null || requiredRoles.isEmpty()) {
                throw new DomainValidationException(
                    "At least one approval role is required."
                );
            }

            this.revisionId = revisionId;
            this.policyName = policyName;
            this.version = version;
            this.createdBy = createdBy;
            this.requiredRoles = Set.copyOf(requiredRoles);
        }

        void approve(String principal, ApprovalRole role) {
            if (state != RevisionState.DRAFT) {
                throw new PolicyTransitionException(
                    "Only draft revisions can receive approvals."
                );
            }

            if (principal == null || principal.isBlank() || role == null) {
                throw new DomainValidationException(
                    "Approver identity and role are required."
                );
            }

            if (principal.equals(createdBy)) {
                throw new PolicyTransitionException(
                    "The revision creator cannot approve the revision."
                );
            }

            if (!requiredRoles.contains(role)) {
                throw new PolicyTransitionException(
                    "Approver role is not authorized for this policy."
                );
            }

            if (approvals.containsKey(principal)) {
                throw new PolicyTransitionException(
                    "A principal can approve only once."
                );
            }

            approvals.put(principal, role);
        }

        void activate() {
            if (state != RevisionState.DRAFT) {
                throw new PolicyTransitionException(
                    "Only a draft revision can become active."
                );
            }

            Set<ApprovalRole> approvedRoles =
                new HashSet<>(approvals.values());

            if (!approvedRoles.containsAll(requiredRoles)) {
                throw new PolicyTransitionException(
                    "Required policy approvals are incomplete."
                );
            }

            state = RevisionState.ACTIVE;
        }

        void retire() {
            if (state != RevisionState.ACTIVE) {
                throw new PolicyTransitionException(
                    "Only active revisions can be retired."
                );
            }

            state = RevisionState.RETIRED;
        }

        String revisionId() {
            return revisionId;
        }

        String policyName() {
            return policyName;
        }

        int version() {
            return version;
        }

        RevisionState state() {
            return state;
        }

        Set<ApprovalRole> requiredRoles() {
            return requiredRoles;
        }

        int approvalCount() {
            return approvals.size();
        }
    }

    /**
     * The service evaluates only an active, approved policy revision.
     */
    static final class NetworkPolicyService {

        private final NetworkInventory inventory;
        private final PolicyRevision revision;
        private final List<NetworkRule> networkRules;
        private final List<MicroRule> microRules;
        private final List<Evaluation> auditLog = new ArrayList<>();
        private final Set<String> processedFlowIds = new HashSet<>();

        NetworkPolicyService(
            NetworkInventory inventory,
            PolicyRevision revision,
            List<NetworkRule> networkRules,
            List<MicroRule> microRules
        ) {
            if (revision.state() != RevisionState.ACTIVE) {
                throw new PolicyTransitionException(
                    "An active policy revision is required."
                );
            }

            this.inventory = inventory;
            this.revision = revision;

            this.networkRules = prepareRules(
                networkRules,
                NetworkRule::id,
                NetworkRule::priority
            );

            this.microRules = prepareRules(
                microRules,
                MicroRule::id,
                MicroRule::priority
            );
        }

        private <T> List<T> prepareRules(
            List<T> input,
            java.util.function.Function<T, String> idGetter,
            java.util.function.ToIntFunction<T> priorityGetter
        ) {
            List<T> result = new ArrayList<>(input);
            Set<String> identifiers = new HashSet<>();
            Set<Integer> priorities = new HashSet<>();

            for (T rule : result) {
                if (!identifiers.add(idGetter.apply(rule))) {
                    throw new DomainValidationException(
                        "Duplicate policy rule ID."
                    );
                }

                if (!priorities.add(priorityGetter.apply(rule))) {
                    throw new DomainValidationException(
                        "Duplicate rule priority is not permitted."
                    );
                }
            }

            result.sort(
                Comparator.comparingInt(priorityGetter)
                    .thenComparing(idGetter)
            );

            return List.copyOf(result);
        }

        private Action findNetworkAction(
            Zone sourceZone,
            Zone destinationZone,
            TrafficFlow flow
        ) {
            return networkRules.stream()
                .filter(rule ->
                    rule.sourceZone() == sourceZone &&
                    rule.destinationZone() == destinationZone &&
                    rule.protocol() == flow.protocol() &&
                    flow.destinationPort() >= rule.portFrom() &&
                    flow.destinationPort() <= rule.portTo()
                )
                .map(NetworkRule::action)
                .findFirst()
                .orElse(Action.DENY);
        }

        private Action findMicroAction(
            Endpoint source,
            Endpoint destination,
            TrafficFlow flow
        ) {
            return microRules.stream()
                .filter(rule ->
                    (
                        rule.sourceRole().equals("*") ||
                        rule.sourceRole().equals(source.role())
                    ) &&
                    (
                        rule.destinationRole().equals("*") ||
                        rule.destinationRole().equals(destination.role())
                    ) &&
                    rule.protocol() == flow.protocol() &&
                    flow.destinationPort() >= rule.portFrom() &&
                    flow.destinationPort() <= rule.portTo()
                )
                .map(MicroRule::action)
                .findFirst()
                .orElse(Action.DENY);
        }

        Evaluation evaluate(TrafficFlow flow) {
            if (revision.state() != RevisionState.ACTIVE) {
                throw new PolicyTransitionException(
                    "The policy is not active."
                );
            }

            if (!processedFlowIds.add(flow.id())) {
                throw new DomainValidationException(
                    "Duplicate flow ID: " + flow.id()
                );
            }

            Endpoint source = inventory.getEndpoint(flow.sourceId());
            Endpoint destination =
                inventory.getEndpoint(flow.destinationId());

            Segment sourceSegment =
                inventory.getSegment(source.segmentId());

            Segment destinationSegment =
                inventory.getSegment(destination.segmentId());

            boolean sameSegment =
                source.segmentId().equals(destination.segmentId());

            TrafficClass trafficClass;

            if (
                sourceSegment.zone() == Zone.INTERNET ||
                destinationSegment.zone() == Zone.INTERNET
            ) {
                trafficClass = TrafficClass.NORTH_SOUTH;
            } else if (sameSegment) {
                trafficClass = TrafficClass.INTRA_SEGMENT;
            } else {
                trafficClass = TrafficClass.EAST_WEST;
            }

            Action networkAction = sameSegment
                ? Action.ALLOW
                : findNetworkAction(
                    sourceSegment.zone(),
                    destinationSegment.zone(),
                    flow
                );

            Action microAction = findMicroAction(
                source,
                destination,
                flow
            );

            boolean allowed =
                networkAction == Action.ALLOW &&
                microAction == Action.ALLOW;

            String networkResult = sameSegment
                ? "NOT_REQUIRED"
                : networkAction.name();

            String reason;

            if (networkAction == Action.DENY) {
                reason = "NETWORK_BOUNDARY_DENY";
            } else if (microAction == Action.DENY) {
                reason = "MICROSEGMENTATION_DEFAULT_DENY";
            } else {
                reason = "BOTH_POLICY_LAYERS_ALLOW";
            }

            Evaluation evaluation = new Evaluation(
                flow.id(),
                trafficClass,
                allowed,
                networkResult,
                microAction.name(),
                reason
            );

            auditLog.add(evaluation);
            return evaluation;
        }

        List<Evaluation> auditLog() {
            return List.copyOf(auditLog);
        }
    }

    static NetworkInventory buildInventory() {
        NetworkInventory inventory = new NetworkInventory();

        inventory.addSegment(
            new Segment(
                "users", "User VLAN", 10,
                "10.10.0.0/24", Zone.USER
            )
        );

        inventory.addSegment(
            new Segment(
                "dmz", "DMZ", 20,
                "10.20.0.0/24", Zone.DMZ
            )
        );

        inventory.addSegment(
            new Segment(
                "apps", "Application VLAN", 30,
                "10.30.0.0/24", Zone.APPLICATION
            )
        );

        inventory.addSegment(
            new Segment(
                "data", "Database VLAN", 40,
                "10.40.0.0/24", Zone.DATA
            )
        );

        inventory.addSegment(
            new Segment(
                "management", "Management VLAN", 50,
                "10.50.0.0/24", Zone.MANAGEMENT
            )
        );

        inventory.addSegment(
            new Segment(
                "internet", "External Test VLAN", 900,
                "198.51.100.0/24", Zone.INTERNET
            )
        );

        inventory.addEndpoint(
            new Endpoint(
                "workstation-01", "users", "10.10.0.10",
                Map.of("role", "employee")
            )
        );

        inventory.addEndpoint(
            new Endpoint(
                "web-01", "dmz", "10.20.0.10",
                Map.of("role", "web")
            )
        );

        inventory.addEndpoint(
            new Endpoint(
                "api-01", "apps", "10.30.0.10",
                Map.of("role", "api")
            )
        );

        inventory.addEndpoint(
            new Endpoint(
                "api-02", "apps", "10.30.0.11",
                Map.of("role", "api")
            )
        );

        inventory.addEndpoint(
            new Endpoint(
                "db-01", "data", "10.40.0.10",
                Map.of("role", "database")
            )
        );

        inventory.addEndpoint(
            new Endpoint(
                "admin-01", "management", "10.50.0.10",
                Map.of("role", "administrator")
            )
        );

        inventory.addEndpoint(
            new Endpoint(
                "external-client", "internet", "198.51.100.10",
                Map.of("role", "internet-client")
            )
        );

        return inventory;
    }

    static List<NetworkRule> buildNetworkRules() {
        return List.of(
            new NetworkRule(
                "NET-001", 10, Zone.INTERNET, Zone.DMZ,
                Protocol.TCP, 443, 443, Action.ALLOW
            ),
            new NetworkRule(
                "NET-002", 20, Zone.USER, Zone.DMZ,
                Protocol.TCP, 443, 443, Action.ALLOW
            ),
            new NetworkRule(
                "NET-003", 30, Zone.DMZ, Zone.APPLICATION,
                Protocol.TCP, 8443, 8443, Action.ALLOW
            ),
            new NetworkRule(
                "NET-004", 40, Zone.APPLICATION, Zone.DATA,
                Protocol.TCP, 5432, 5432, Action.ALLOW
            ),
            new NetworkRule(
                "NET-005", 50, Zone.MANAGEMENT, Zone.APPLICATION,
                Protocol.TCP, 22, 22, Action.ALLOW
            )
        );
    }

    static List<MicroRule> buildMicroRules() {
        return List.of(
            new MicroRule(
                "MICRO-001", 10, "internet-client", "web",
                Protocol.TCP, 443, 443, Action.ALLOW
            ),
            new MicroRule(
                "MICRO-002", 20, "employee", "web",
                Protocol.TCP, 443, 443, Action.ALLOW
            ),
            new MicroRule(
                "MICRO-003", 30, "web", "api",
                Protocol.TCP, 8443, 8443, Action.ALLOW
            ),
            new MicroRule(
                "MICRO-004", 40, "api", "database",
                Protocol.TCP, 5432, 5432, Action.ALLOW
            ),
            new MicroRule(
                "MICRO-005", 50, "administrator", "api",
                Protocol.TCP, 22, 22, Action.ALLOW
            )
        );
    }

    static void verifyExpectedFailure(Runnable operation) {
        try {
            operation.run();
        } catch (
            PolicyTransitionException |
            DomainValidationException expected
        ) {
            System.out.println(
                "Rejected invalid operation: " + expected.getMessage()
            );
            return;
        }

        throw new IllegalStateException(
            "An invalid policy operation was accepted."
        );
    }

    public static void main(String[] args) {
        try {
            NetworkInventory inventory = buildInventory();

            PolicyRevision revision = new PolicyRevision(
                "REV-104",
                "Production Network Segmentation",
                1,
                "release-bot",
                EnumSet.of(
                    ApprovalRole.NETWORK_SECURITY,
                    ApprovalRole.PLATFORM_OPERATIONS
                )
            );

            // Separation of duties prevents the revision creator from
            // approving their own network policy change.
            verifyExpectedFailure(
                () -> revision.approve(
                    "release-bot",
                    ApprovalRole.NETWORK_SECURITY
                )
            );

            revision.approve(
                "security-reviewer",
                ApprovalRole.NETWORK_SECURITY
            );

            verifyExpectedFailure(revision::activate);

            revision.approve(
                "operations-reviewer",
                ApprovalRole.PLATFORM_OPERATIONS
            );

            revision.activate();

            NetworkPolicyService service = new NetworkPolicyService(
                inventory,
                revision,
                buildNetworkRules(),
                buildMicroRules()
            );

            List<TrafficFlow> flows = List.of(
                new TrafficFlow(
                    "FLOW-001", "external-client", "web-01",
                    Protocol.TCP, 443
                ),
                new TrafficFlow(
                    "FLOW-002", "workstation-01", "web-01",
                    Protocol.TCP, 443
                ),
                new TrafficFlow(
                    "FLOW-003", "web-01", "api-01",
                    Protocol.TCP, 8443
                ),
                new TrafficFlow(
                    "FLOW-004", "api-01", "db-01",
                    Protocol.TCP, 5432
                ),
                new TrafficFlow(
                    "FLOW-005", "web-01", "db-01",
                    Protocol.TCP, 5432
                ),
                new TrafficFlow(
                    "FLOW-006", "api-01", "api-02",
                    Protocol.TCP, 8080
                ),
                new TrafficFlow(
                    "FLOW-007", "admin-01", "api-01",
                    Protocol.TCP, 22
                )
            );

            int allowed = 0;
            int denied = 0;

            System.out.println("\nENTERPRISE NETWORK POLICY REPORT");
            System.out.println(
                "Revision: " + revision.revisionId() +
                " | Version: " + revision.version() +
                " | State: " + revision.state()
            );

            for (TrafficFlow flow : flows) {
                Evaluation result = service.evaluate(flow);

                if (result.allowed()) {
                    allowed++;
                } else {
                    denied++;
                }

                System.out.printf(
                    "%s | %-15s | %-5s | Network=%-12s | Micro=%-5s | %s%n",
                    result.flowId(),
                    result.trafficClass(),
                    result.allowed() ? "ALLOW" : "DENY",
                    result.networkResult(),
                    result.microResult(),
                    result.reason()
                );
            }

            if (allowed != 5 || denied != 2) {
                throw new IllegalStateException(
                    "Unexpected traffic policy results."
                );
            }

            System.out.println("\nPOLICY REPORT");
            System.out.println("Segments: " + inventory.segmentCount());
            System.out.println("Endpoints: " + inventory.endpointCount());
            System.out.println("Approvals: " + revision.approvalCount());
            System.out.println("Allowed:   " + allowed);
            System.out.println("Denied:    " + denied);
            System.out.println(
                "Evaluations: " + service.auditLog().size()
            );

            revision.retire();

            System.out.println(
                "Revision lifecycle completed: " + revision.state()
            );

        } catch (RuntimeException exception) {
            System.err.println(
                "Network governance failure: " + exception.getMessage()
            );
            System.exit(1);
        }
    }
}
