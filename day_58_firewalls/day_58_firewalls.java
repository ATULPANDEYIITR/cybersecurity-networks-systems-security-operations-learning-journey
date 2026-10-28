import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public class FirewallGovernance {

    enum Action {
        ALLOW,
        DENY
    }

    enum Protocol {
        TCP,
        UDP,
        ICMP
    }

    enum Direction {
        INBOUND,
        OUTBOUND
    }

    enum FirewallState {
        NEW,
        ESTABLISHED
    }

    enum Zone {
        INTERNET,
        DMZ,
        INTERNAL,
        UNTRUSTED
    }

    static final class FirewallException extends RuntimeException {
        FirewallException(String message) {
            super(message);
        }
    }

    record IPv4(int value) {

        static IPv4 parse(String text) {
            Objects.requireNonNull(text, "IPv4 address is required");

            String[] parts = text.split("\\.", -1);

            if (parts.length != 4) {
                throw new FirewallException("Invalid IPv4 address: " + text);
            }

            int result = 0;

            for (String part : parts) {
                int octet;

                try {
                    octet = Integer.parseInt(part);
                } catch (NumberFormatException exception) {
                    throw new FirewallException(
                        "Invalid IPv4 address: " + text
                    );
                }

                if (octet < 0 || octet > 255) {
                    throw new FirewallException(
                        "IPv4 octet outside range: " + text
                    );
                }

                result = (result << 8) | octet;
            }

            return new IPv4(result);
        }

        @Override
        public String toString() {
            return String.format(
                "%d.%d.%d.%d",
                (value >>> 24) & 255,
                (value >>> 16) & 255,
                (value >>> 8) & 255,
                value & 255
            );
        }
    }

    record Network(IPv4 address, int prefix) {

        Network {
            if (prefix < 0 || prefix > 32) {
                throw new FirewallException(
                    "CIDR prefix must be between 0 and 32"
                );
            }
        }

        boolean contains(IPv4 candidate) {
            if (prefix == 0) {
                return true;
            }

            int mask = -1 << (32 - prefix);
            return (candidate.value() & mask) ==
                   (address.value() & mask);
        }
    }

    record Packet(
        IPv4 source,
        IPv4 destination,
        Protocol protocol,
        Integer sourcePort,
        Integer destinationPort,
        Direction direction,
        String interfaceName
    ) {

        Packet {
            Objects.requireNonNull(source);
            Objects.requireNonNull(destination);
            Objects.requireNonNull(protocol);
            Objects.requireNonNull(direction);

            boolean usesPorts =
                protocol == Protocol.TCP ||
                protocol == Protocol.UDP;

            if (usesPorts) {
                validatePort(sourcePort, "source");
                validatePort(destinationPort, "destination");
            } else if (sourcePort != null || destinationPort != null) {
                throw new FirewallException(
                    "ICMP packets cannot use TCP/UDP ports"
                );
            }
        }

        private static void validatePort(
            Integer port,
            String field
        ) {
            if (
                port == null ||
                port < 1 ||
                port > 65535
            ) {
                throw new FirewallException(
                    "Invalid " + field + " port"
                );
            }
        }

        FlowKey flowKey() {
            return new FlowKey(
                source,
                destination,
                protocol,
                sourcePort,
                destinationPort
            );
        }
    }

    record FlowKey(
        IPv4 source,
        IPv4 destination,
        Protocol protocol,
        Integer sourcePort,
        Integer destinationPort
    ) {
        FlowKey reverse() {
            return new FlowKey(
                destination,
                source,
                protocol,
                destinationPort,
                sourcePort
            );
        }
    }

    record Rule(
        String name,
        Action action,
        Protocol protocol,
        Network sourceNetwork,
        Network destinationNetwork,
        Integer sourcePort,
        Integer destinationPort,
        Direction direction,
        String interfaceName
    ) {

        boolean matches(Packet packet) {
            return
                (protocol == null || protocol == packet.protocol()) &&
                (sourceNetwork == null ||
                    sourceNetwork.contains(packet.source())) &&
                (destinationNetwork == null ||
                    destinationNetwork.contains(packet.destination())) &&
                (sourcePort == null ||
                    sourcePort.equals(packet.sourcePort())) &&
                (destinationPort == null ||
                    destinationPort.equals(packet.destinationPort())) &&
                (direction == null ||
                    direction == packet.direction()) &&
                (interfaceName == null ||
                    interfaceName.equals(packet.interfaceName()));
        }
    }

    record Decision(
        Action action,
        String rule,
        String reason,
        FirewallState state
    ) {}

    interface Policy {
        boolean permits(Packet packet);

        Action action();

        String name();
    }

    static final class AllowHttpsPolicy implements Policy {

        @Override
        public boolean permits(Packet packet) {
            return packet.protocol() == Protocol.TCP &&
                packet.destinationPort() == 443;
        }

        @Override
        public Action action() {
            return Action.ALLOW;
        }

        @Override
        public String name() {
            return "ALLOW-HTTPS";
        }
    }

    static final class DenyTelnetPolicy implements Policy {

        @Override
        public boolean permits(Packet packet) {
            return packet.protocol() == Protocol.TCP &&
                packet.destinationPort() == 23;
        }

        @Override
        public Action action() {
            return Action.DENY;
        }

        @Override
        public String name() {
            return "DENY-TELNET";
        }
    }

    static final class StatefulFirewall {

        private final List<Rule> rules;
        private final Set<FlowKey> establishedFlows =
            new HashSet<>();

        private final Action defaultAction;

        StatefulFirewall(
            List<Rule> rules,
            Action defaultAction
        ) {
            this.rules = List.copyOf(rules);
            this.defaultAction = defaultAction;
        }

        Decision evaluate(Packet packet) {
            FlowKey key = packet.flowKey();

            if (
                establishedFlows.contains(key) ||
                establishedFlows.contains(key.reverse())
            ) {
                return new Decision(
                    Action.ALLOW,
                    "STATEFUL-ESTABLISHED",
                    "Reverse or forward flow is already established",
                    FirewallState.ESTABLISHED
                );
            }

            for (Rule rule : rules) {
                if (rule.matches(packet)) {
                    if (rule.action() == Action.ALLOW) {
                        establishedFlows.add(key);
                    }

                    return new Decision(
                        rule.action(),
                        rule.name(),
                        "First matching rule",
                        rule.action() == Action.ALLOW
                            ? FirewallState.ESTABLISHED
                            : FirewallState.NEW
                    );
                }
            }

            return new Decision(
                defaultAction,
                "DEFAULT-DENY",
                "No configured rule matched",
                FirewallState.NEW
            );
        }

        int trackedFlowCount() {
            return establishedFlows.size();
        }
    }

    static final class ZonePolicy {

        private final Zone sourceZone;
        private final Zone destinationZone;
        private final Action action;
        private final Protocol protocol;
        private final Integer destinationPort;

        ZonePolicy(
            Zone sourceZone,
            Zone destinationZone,
            Action action,
            Protocol protocol,
            Integer destinationPort
        ) {
            this.sourceZone = sourceZone;
            this.destinationZone = destinationZone;
            this.action = action;
            this.protocol = protocol;
            this.destinationPort = destinationPort;
        }

        boolean matches(
            Zone source,
            Zone destination,
            Packet packet
        ) {
            return sourceZone == source &&
                destinationZone == destination &&
                (protocol == null || protocol == packet.protocol()) &&
                (destinationPort == null ||
                    destinationPort.equals(packet.destinationPort()));
        }

        Action action() {
            return action;
        }

        String name() {
            return sourceZone + "->" + destinationZone;
        }
    }

    static final class ZoneFirewall {

        private final Map<Zone, List<Network>> networks;
        private final List<ZonePolicy> policies;
        private final Set<FlowKey> establishedFlows =
            new HashSet<>();

        ZoneFirewall(
            Map<Zone, List<Network>> networks,
            List<ZonePolicy> policies
        ) {
            this.networks = new HashMap<>();

            networks.forEach(
                (zone, values) ->
                    this.networks.put(
                        zone,
                        List.copyOf(values)
                    )
            );

            this.policies = List.copyOf(policies);
        }

        Zone classify(IPv4 ip) {
            List<Zone> matches = networks.entrySet()
                .stream()
                .filter(entry ->
                    entry.getValue()
                        .stream()
                        .anyMatch(network -> network.contains(ip)))
                .map(Map.Entry::getKey)
                .toList();

            if (matches.isEmpty()) {
                return Zone.UNTRUSTED;
            }

            if (matches.size() > 1) {
                throw new FirewallException(
                    "Overlapping zone definitions for " + ip
                );
            }

            return matches.getFirst();
        }

        Decision evaluate(Packet packet) {
            Zone sourceZone = classify(packet.source());
            Zone destinationZone = classify(packet.destination());

            FlowKey key = packet.flowKey();

            if (
                establishedFlows.contains(key) ||
                establishedFlows.contains(key.reverse())
            ) {
                return new Decision(
                    Action.ALLOW,
                    "ZONE-ESTABLISHED",
                    sourceZone + " -> " + destinationZone,
                    FirewallState.ESTABLISHED
                );
            }

            for (ZonePolicy policy : policies) {
                if (
                    policy.matches(
                        sourceZone,
                        destinationZone,
                        packet
                    )
                ) {
                    if (policy.action() == Action.ALLOW) {
                        establishedFlows.add(key);
                    }

                    return new Decision(
                        policy.action(),
                        policy.name(),
                        "Zone policy matched",
                        policy.action() == Action.ALLOW
                            ? FirewallState.ESTABLISHED
                            : FirewallState.NEW
                    );
                }
            }

            return new Decision(
                Action.DENY,
                "ZONE-DEFAULT-DENY",
                sourceZone + " -> " + destinationZone +
                    " has no explicit permit",
                FirewallState.NEW
            );
        }
    }

    static Rule allowHttpsInbound() {
        return new Rule(
            "ALLOW-HTTPS-INBOUND",
            Action.ALLOW,
            Protocol.TCP,
            null,
            new Network(
                IPv4.parse("10.0.10.0"),
                24
            ),
            null,
            443,
            Direction.INBOUND,
            "external"
        );
    }

    static Rule allowDnsOutbound() {
        return new Rule(
            "ALLOW-DNS-OUTBOUND",
            Action.ALLOW,
            Protocol.UDP,
            new Network(
                IPv4.parse("10.0.20.0"),
                24
            ),
            null,
            null,
            53,
            Direction.OUTBOUND,
            "internal"
        );
    }

    static Rule denyTelnet() {
        return new Rule(
            "DENY-TELNET",
            Action.DENY,
            Protocol.TCP,
            null,
            null,
            null,
            23,
            null,
            null
        );
    }

    static Packet tcp(
        String source,
        String destination,
        int sourcePort,
        int destinationPort,
        Direction direction,
        String interfaceName
    ) {
        return new Packet(
            IPv4.parse(source),
            IPv4.parse(destination),
            Protocol.TCP,
            sourcePort,
            destinationPort,
            direction,
            interfaceName
        );
    }

    static Packet udp(
        String source,
        String destination,
        int sourcePort,
        int destinationPort,
        Direction direction,
        String interfaceName
    ) {
        return new Packet(
            IPv4.parse(source),
            IPv4.parse(destination),
            Protocol.UDP,
            sourcePort,
            destinationPort,
            direction,
            interfaceName
        );
    }

    static void printDecision(
        Packet packet,
        Decision decision
    ) {
        System.out.printf(
            "%s:%s -> %s:%s %s: %s [%s] %s%n",
            packet.source(),
            packet.sourcePort(),
            packet.destination(),
            packet.destinationPort(),
            packet.protocol(),
            decision.action(),
            decision.rule(),
            decision.reason()
        );
    }

    public static void main(String[] args) {
        List<Rule> rules = List.of(
            allowHttpsInbound(),
            allowDnsOutbound(),
            denyTelnet()
        );

        StatefulFirewall firewall =
            new StatefulFirewall(
                rules,
                Action.DENY
            );

        List<Packet> traffic = List.of(
            tcp(
                "203.0.113.10",
                "10.0.10.20",
                45000,
                443,
                Direction.INBOUND,
                "external"
            ),
            tcp(
                "10.0.10.20",
                "203.0.113.10",
                443,
                45000,
                Direction.OUTBOUND,
                "internal"
            ),
            udp(
                "10.0.20.10",
                "8.8.8.8",
                51000,
                53,
                Direction.OUTBOUND,
                "internal"
            ),
            tcp(
                "203.0.113.10",
                "10.0.20.10",
                45001,
                22,
                Direction.INBOUND,
                "external"
            ),
            tcp(
                "203.0.113.10",
                "10.0.20.10",
                45002,
                23,
                Direction.INBOUND,
                "external"
            )
        );

        System.out.println("ENTERPRISE FIREWALL EVALUATION");

        traffic.forEach(packet ->
            printDecision(
                packet,
                firewall.evaluate(packet)
            )
        );

        System.out.println(
            "\nTracked established flows: " +
            firewall.trackedFlowCount()
        );

        Map<Zone, List<Network>> zones = Map.of(
            Zone.INTERNET,
            List.of(
                new Network(
                    IPv4.parse("0.0.0.0"),
                    1
                ),
                new Network(
                    IPv4.parse("128.0.0.0"),
                    1
                )
            ),
            Zone.DMZ,
            List.of(
                new Network(
                    IPv4.parse("10.0.10.0"),
                    24
                )
            ),
            Zone.INTERNAL,
            List.of(
                new Network(
                    IPv4.parse("10.0.20.0"),
                    24
                )
            )
        );

        List<ZonePolicy> zonePolicies = List.of(
            new ZonePolicy(
                Zone.INTERNET,
                Zone.DMZ,
                Action.ALLOW,
                Protocol.TCP,
                443
            ),
            new ZonePolicy(
                Zone.INTERNAL,
                Zone.INTERNET,
                Action.ALLOW,
                Protocol.TCP,
                443
            ),
            new ZonePolicy(
                Zone.INTERNAL,
                Zone.INTERNET,
                Action.ALLOW,
                Protocol.UDP,
                53
            )
        );

        ZoneFirewall zoneFirewall =
            new ZoneFirewall(
                zones,
                zonePolicies
            );

        System.out.println("\nZONE POLICY EVALUATION");

        printDecision(
            traffic.getFirst(),
            zoneFirewall.evaluate(
                traffic.getFirst()
            )
        );

        printDecision(
            traffic.get(2),
            zoneFirewall.evaluate(
                traffic.get(2)
            )
        );

        printDecision(
            traffic.get(3),
            zoneFirewall.evaluate(
                traffic.get(3)
            )
        );

        Packet unmatched = tcp(
            "203.0.113.50",
            "10.0.10.20",
            50000,
            22,
            Direction.INBOUND,
            "external"
        );

        Decision unmatchedDecision =
            firewall.evaluate(unmatched);

        if (unmatchedDecision.action() != Action.DENY) {
            throw new FirewallException(
                "Default-deny security invariant failed"
            );
        }

        System.out.println(
            "\nDefault-deny invariant verified."
        );

        try {
            new Packet(
                IPv4.parse("10.0.0.1"),
                IPv4.parse("10.0.0.2"),
                Protocol.TCP,
                null,
                443,
                Direction.OUTBOUND,
                "internal"
            );

            throw new FirewallException(
                "Malformed packet was accepted"
            );
        } catch (FirewallException expected) {
            System.out.println(
                "Packet validation invariant verified."
            );
        }
    }
}
