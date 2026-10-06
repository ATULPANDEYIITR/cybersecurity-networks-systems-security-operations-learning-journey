import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/*
 * Linux Networking Enterprise Diagnostic Model
 *
 * Scenario:
 * A Java-based operations service evaluates the network environment of a Linux
 * application host before starting a dependent service.
 *
 * The model separates:
 *   Interface inventory
 *   Route selection
 *   DNS configuration
 *   TCP connectivity
 *   Firewall policy
 *
 * Compile:
 *   javac LinuxNetworkingEnterprise.java
 *
 * Run:
 *   java LinuxNetworkingEnterprise
 *
 * Java 17 or later is required.
 */

public class LinuxNetworkingEnterprise {

    enum Protocol {
        TCP,
        UDP
    }

    enum FirewallAction {
        ACCEPT,
        DROP
    }

    record InterfaceAddress(
        String address,
        short prefixLength,
        boolean loopback
    ) {
    }

    record NetworkInterfaceSnapshot(
        String name,
        boolean up,
        int mtu,
        List<InterfaceAddress> addresses
    ) {
        NetworkInterfaceSnapshot {
            addresses = List.copyOf(addresses);
        }
    }

    record Route(
        String network,
        int prefixLength,
        String gateway,
        String device,
        int metric
    ) {
    }

    record Packet(
        Protocol protocol,
        String sourceIp,
        String destinationIp,
        int destinationPort
    ) {
    }

    record FirewallRule(
        FirewallAction action,
        Protocol protocol,
        String sourceNetwork,
        int destinationPort,
        String description
    ) {
        boolean matches(Packet packet) {
            if (protocol != null && protocol != packet.protocol()) {
                return false;
            }

            if (
                sourceNetwork != null &&
                !Ipv4.cidrContains(sourceNetwork, packet.sourceIp())
            ) {
                return false;
            }

            return destinationPort == 0 ||
                   destinationPort == packet.destinationPort();
        }
    }

    record FirewallDecision(
        FirewallAction action,
        String reason
    ) {
    }

    static final class Ipv4 {

        private Ipv4() {
        }

        static long toInteger(String address) {
            String[] parts = address.split("\\.");

            if (parts.length != 4) {
                throw new IllegalArgumentException(
                    "Invalid IPv4 address: " + address
                );
            }

            long result = 0;

            for (String part : parts) {
                int value;

                try {
                    value = Integer.parseInt(part);
                } catch (NumberFormatException exception) {
                    throw new IllegalArgumentException(
                        "Invalid IPv4 address: " + address,
                        exception
                    );
                }

                if (value < 0 || value > 255) {
                    throw new IllegalArgumentException(
                        "Invalid IPv4 octet: " + part
                    );
                }

                result = (result << 8) | value;
            }

            return result;
        }

        static boolean cidrContains(String cidr, String address) {
            String[] pieces = cidr.split("/");

            if (pieces.length != 2) {
                throw new IllegalArgumentException(
                    "Invalid CIDR: " + cidr
                );
            }

            int prefix = Integer.parseInt(pieces[1]);

            if (prefix < 0 || prefix > 32) {
                throw new IllegalArgumentException(
                    "Invalid CIDR prefix: " + prefix
                );
            }

            if (prefix == 0) {
                return true;
            }

            long mask = (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;

            return (toInteger(pieces[0]) & mask) ==
                   (toInteger(address) & mask);
        }
    }

    static final class NetworkInventoryService {

        List<NetworkInterfaceSnapshot> inspectInterfaces()
            throws SocketException {

            List<NetworkInterfaceSnapshot> snapshots = new ArrayList<>();

            Enumeration<NetworkInterface> interfaces =
                NetworkInterface.getNetworkInterfaces();

            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface =
                    interfaces.nextElement();

                List<InterfaceAddress> addresses = new ArrayList<>();

                for (
                    java.net.InterfaceAddress address :
                    networkInterface.getInterfaceAddresses()
                ) {
                    InetAddress inetAddress = address.getAddress();

                    if (inetAddress == null) {
                        continue;
                    }

                    /*
                     * InterfaceAddress exposes the prefix length directly,
                     * which is more useful for CIDR-oriented diagnostics than
                     * storing only a human-readable netmask.
                     */
                    addresses.add(
                        new InterfaceAddress(
                            inetAddress.getHostAddress(),
                            address.getNetworkPrefixLength(),
                            inetAddress.isLoopbackAddress()
                        )
                    );
                }

                snapshots.add(
                    new NetworkInterfaceSnapshot(
                        networkInterface.getName(),
                        networkInterface.isUp(),
                        networkInterface.getMTU(),
                        addresses
                    )
                );
            }

            return snapshots;
        }
    }

    static final class RouteEngine {

        private final List<Route> routes;

        RouteEngine(List<Route> routes) {
            this.routes = List.copyOf(routes);
        }

        Optional<Route> select(String destination) {
            return routes.stream()
                .filter(
                    route ->
                        Ipv4.cidrContains(
                            route.network() + "/" + route.prefixLength(),
                            destination
                        )
                )
                /*
                 * Longest prefix is preferred. A lower metric is used as the
                 * tie-breaker in this simplified enterprise model.
                 */
                .sorted(
                    Comparator
                        .comparingInt(Route::prefixLength)
                        .reversed()
                        .thenComparingInt(Route::metric)
                )
                .findFirst();
        }
    }

    static final class FirewallPolicy {

        private final List<FirewallRule> rules;
        private final FirewallAction defaultAction;

        FirewallPolicy(
            List<FirewallRule> rules,
            FirewallAction defaultAction
        ) {
            this.rules = List.copyOf(rules);
            this.defaultAction = Objects.requireNonNull(defaultAction);
        }

        FirewallDecision evaluate(Packet packet) {
            for (FirewallRule rule : rules) {
                if (rule.matches(packet)) {
                    return new FirewallDecision(
                        rule.action(),
                        rule.description()
                    );
                }
            }

            return new FirewallDecision(
                defaultAction,
                "default policy"
            );
        }
    }

    static final class DnsService {

        List<String> configuredNameServers() throws IOException {
            Path resolvConf = Path.of("/etc/resolv.conf");

            if (!Files.exists(resolvConf)) {
                return List.of();
            }

            return Files.readAllLines(resolvConf).stream()
                .map(String::trim)
                .filter(line -> line.startsWith("nameserver "))
                .map(line -> line.substring("nameserver ".length()).trim())
                .toList();
        }

        List<String> resolve(String hostname) throws IOException {
            if (
                hostname == null ||
                hostname.isBlank() ||
                hostname.length() > 253 ||
                hostname.chars().anyMatch(Character::isWhitespace)
            ) {
                throw new IllegalArgumentException(
                    "Invalid hostname."
                );
            }

            InetAddress[] addresses = InetAddress.getAllByName(hostname);

            return java.util.Arrays.stream(addresses)
                .map(InetAddress::getHostAddress)
                .distinct()
                .sorted()
                .toList();
        }
    }

    static final class TcpConnectivityService {

        boolean test(String host, int port, Duration timeout) {
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException(
                    "TCP port must be between 1 and 65535."
                );
            }

            long start = System.nanoTime();

            try (Socket socket = new Socket()) {
                socket.connect(
                    new InetSocketAddress(host, port),
                    Math.toIntExact(timeout.toMillis())
                );

                long elapsed =
                    (System.nanoTime() - start) / 1_000_000;

                System.out.printf(
                    "TCP %s:%d connected in %d ms%n",
                    host,
                    port,
                    elapsed
                );

                return true;
            } catch (IOException exception) {
                long elapsed =
                    (System.nanoTime() - start) / 1_000_000;

                System.out.printf(
                    "TCP %s:%d failed after %d ms: %s%n",
                    host,
                    port,
                    elapsed,
                    exception.getMessage()
                );

                return false;
            }
        }
    }

    private static void printInterfaces(
        NetworkInventoryService service
    ) throws SocketException {

        System.out.println("\n=== Linux interface inventory ===");

        for (NetworkInterfaceSnapshot snapshot :
            service.inspectInterfaces()) {

            System.out.printf(
                "%s state=%s mtu=%d%n",
                snapshot.name(),
                snapshot.up() ? "UP" : "DOWN",
                snapshot.mtu()
            );

            for (InterfaceAddress address : snapshot.addresses()) {
                System.out.printf(
                    "  %s/%d%s%n",
                    address.address(),
                    address.prefixLength(),
                    address.loopback() ? " loopback" : ""
                );
            }
        }
    }

    private static void demonstrateRouting() {
        System.out.println("\n=== Route engine ===");

        RouteEngine engine = new RouteEngine(
            List.of(
                new Route(
                    "0.0.0.0",
                    0,
                    "192.0.2.1",
                    "eth0",
                    100
                ),
                new Route(
                    "10.0.0.0",
                    8,
                    "",
                    "eth1",
                    100
                ),
                new Route(
                    "10.20.0.0",
                    16,
                    "10.20.0.1",
                    "eth2",
                    50
                )
            )
        );

        for (String destination :
            List.of(
                "8.8.8.8",
                "10.50.10.20",
                "10.20.4.20"
            )) {

            Optional<Route> route = engine.select(destination);

            System.out.printf(
                "%s -> %s%n",
                destination,
                route.map(
                    selected ->
                        selected.network() +
                        "/" +
                        selected.prefixLength() +
                        " dev=" +
                        selected.device() +
                        " gateway=" +
                        (selected.gateway().isBlank()
                            ? "-"
                            : selected.gateway())
                ).orElse("NO ROUTE")
            );
        }
    }

    private static void demonstrateFirewall() {
        System.out.println("\n=== Firewall policy ===");

        FirewallPolicy policy = new FirewallPolicy(
            List.of(
                new FirewallRule(
                    FirewallAction.ACCEPT,
                    Protocol.TCP,
                    "10.20.0.0/16",
                    22,
                    "SSH administration from management network"
                ),
                new FirewallRule(
                    FirewallAction.ACCEPT,
                    Protocol.TCP,
                    "0.0.0.0/0",
                    443,
                    "Public HTTPS service"
                )
            ),
            FirewallAction.DROP
        );

        List<Packet> packets = List.of(
            new Packet(
                Protocol.TCP,
                "10.20.5.10",
                "192.0.2.20",
                22
            ),
            new Packet(
                Protocol.TCP,
                "198.51.100.5",
                "192.0.2.20",
                22
            ),
            new Packet(
                Protocol.TCP,
                "198.51.100.5",
                "192.0.2.20",
                443
            ),
            new Packet(
                Protocol.UDP,
                "198.51.100.5",
                "192.0.2.20",
                53
            )
        );

        for (Packet packet : packets) {
            FirewallDecision decision = policy.evaluate(packet);

            System.out.printf(
                "%s %s -> %s:%d => %s (%s)%n",
                packet.protocol(),
                packet.sourceIp(),
                packet.destinationIp(),
                packet.destinationPort(),
                decision.action(),
                decision.reason()
            );
        }
    }

    private static void printDns(DnsService service) {
        System.out.println("\n=== DNS configuration ===");

        try {
            List<String> servers =
                service.configuredNameServers();

            if (servers.isEmpty()) {
                System.out.println("No nameserver directives found.");
            } else {
                for (String server : servers) {
                    System.out.println("nameserver " + server);
                }
            }
        } catch (IOException exception) {
            System.out.println(
                "DNS configuration read failed: " +
                exception.getMessage()
            );
        }
    }

    private static void demonstrateDnsResolution(
        DnsService service,
        String hostname
    ) {
        System.out.println(
            "\n=== DNS resolution: " +
            hostname +
            " ==="
        );

        try {
            for (String address : service.resolve(hostname)) {
                System.out.println(address);
            }
        } catch (IOException | IllegalArgumentException exception) {
            System.out.println(
                "DNS resolution failed: " +
                exception.getMessage()
            );
        }
    }

    public static void main(String[] args) {
        NetworkInventoryService inventory =
            new NetworkInventoryService();

        DnsService dnsService = new DnsService();

        try {
            printInterfaces(inventory);
        } catch (SocketException exception) {
            System.err.println(
                "Interface inspection failed: " +
                exception.getMessage()
            );
        }

        demonstrateRouting();
        demonstrateFirewall();
        printDns(dnsService);

        String hostname =
            args.length > 0 ? args[0] : "localhost";

        demonstrateDnsResolution(
            dnsService,
            hostname
        );

        if (args.length >= 3 && args[1].equals("--tcp")) {
            try {
                int port = Integer.parseInt(args[2]);

                new TcpConnectivityService().test(
                    hostname,
                    port,
                    Duration.ofSeconds(3)
                );
            } catch (NumberFormatException exception) {
                System.err.println("Invalid TCP port.");
            }
        }

        System.out.println(
            "\nFirewall policy was evaluated in memory; "
            + "no host firewall configuration was modified."
        );
    }
}
