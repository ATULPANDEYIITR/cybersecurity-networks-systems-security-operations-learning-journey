import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;

/*
 * Enterprise Windows configuration governance.
 *
 * Java 17 or later. Standard library only.
 *
 * The application models endpoint identities, service deployment policy,
 * registry configuration ownership, filesystem ACL intent, and audit
 * findings. It does not modify a real Windows machine.
 */

public class WindowsGovernance {
    enum PrivilegeClass {
        STANDARD,
        SERVICE_IDENTITY,
        ADMINISTRATOR
    }

    enum ServiceStatus {
        RUNNING,
        STOPPED,
        DISABLED
    }

    enum RegistryValueType {
        STRING,
        DWORD,
        QWORD,
        BINARY,
        MULTI_STRING
    }

    enum Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        INFORMATIONAL
    }

    enum FileRight {
        READ,
        WRITE,
        EXECUTE,
        DELETE,
        CHANGE_PERMISSIONS
    }

    record Identity(
        String sid,
        String name,
        PrivilegeClass privilegeClass,
        boolean enabled,
        Set<String> groups
    ) {
        Identity {
            if (sid == null || sid.isBlank()) {
                throw new IllegalArgumentException("SID is required.");
            }
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("Identity name is required.");
            }
            Objects.requireNonNull(privilegeClass);
            groups = Set.copyOf(Objects.requireNonNull(groups));
        }
    }

    record ServiceDefinition(
        String name,
        String executablePath,
        String runAsSid,
        ServiceStatus status,
        boolean automaticStart,
        boolean writableByStandardUsers,
        boolean unquotedPathWithSpaces
    ) {
        ServiceDefinition {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("Service name is required.");
            }
            if (executablePath == null || executablePath.isBlank()) {
                throw new IllegalArgumentException("Executable path is required.");
            }
            if (runAsSid == null || runAsSid.isBlank()) {
                throw new IllegalArgumentException("Service identity SID is required.");
            }
            Objects.requireNonNull(status);
        }
    }

    record RegistrySetting(
        String keyPath,
        String valueName,
        RegistryValueType valueType,
        String value,
        String ownerSid,
        boolean machineWide
    ) {
        RegistrySetting {
            if (keyPath == null || !keyPath.matches(
                    "(?i)(HKLM|HKCU|HKCR|HKU|HKCC)\\\\.*")) {
                throw new IllegalArgumentException(
                    "Registry path must identify a root hive and subkey."
                );
            }
            if (valueName == null || valueName.isBlank()) {
                throw new IllegalArgumentException("Registry value name is required.");
            }
            Objects.requireNonNull(valueType);
            if (value == null) {
                throw new IllegalArgumentException("Registry value is required.");
            }
            if (ownerSid == null || ownerSid.isBlank()) {
                throw new IllegalArgumentException("Registry owner SID is required.");
            }
            if (valueType == RegistryValueType.DWORD) {
                try {
                    long number = Long.parseLong(value);
                    if (number < 0 || number > 0xFFFF_FFFFL) {
                        throw new IllegalArgumentException("DWORD is out of range.");
                    }
                } catch (NumberFormatException exception) {
                    throw new IllegalArgumentException(
                        "DWORD values must be unsigned decimal integers."
                    );
                }
            }
        }
    }

    record FileAclEntry(
        String principalSid,
        Set<FileRight> allowed,
        Set<FileRight> denied
    ) {
        FileAclEntry {
            if (principalSid == null || principalSid.isBlank()) {
                throw new IllegalArgumentException("ACL principal SID is required.");
            }
            allowed = Set.copyOf(Objects.requireNonNull(allowed));
            denied = Set.copyOf(Objects.requireNonNull(denied));
        }

        Set<FileRight> simplifiedEffectiveRights() {
            EnumSet<FileRight> effective = EnumSet.noneOf(FileRight.class);
            effective.addAll(allowed);
            effective.removeAll(denied);
            return Collections.unmodifiableSet(effective);
        }
    }

    record AuditFinding(
        Severity severity,
        String resource,
        String message,
        String remediation
    ) {}

    static final class GovernanceRepository {
        private final Map<String, Identity> identities = new TreeMap<>();
        private final Map<String, ServiceDefinition> services = new TreeMap<>();
        private final Map<String, RegistrySetting> settings = new LinkedHashMap<>();
        private final Map<String, List<FileAclEntry>> fileAcls = new LinkedHashMap<>();

        void registerIdentity(Identity identity) {
            Objects.requireNonNull(identity);

            if (identities.putIfAbsent(identity.sid(), identity) != null) {
                throw new IllegalArgumentException("Duplicate identity SID.");
            }
        }

        void registerService(ServiceDefinition service) {
            Objects.requireNonNull(service);

            if (!identities.containsKey(service.runAsSid())) {
                throw new IllegalArgumentException(
                    "Service references an unregistered identity."
                );
            }

            if (services.putIfAbsent(service.name(), service) != null) {
                throw new IllegalArgumentException("Duplicate service name.");
            }
        }

        void registerRegistrySetting(RegistrySetting setting) {
            Objects.requireNonNull(setting);

            if (!identities.containsKey(setting.ownerSid())) {
                throw new IllegalArgumentException(
                    "Registry setting owner is unknown."
                );
            }

            String key = setting.keyPath().toLowerCase()
                + "|" + setting.valueName().toLowerCase();

            if (settings.putIfAbsent(key, setting) != null) {
                throw new IllegalArgumentException(
                    "Duplicate registry value in the same key."
                );
            }
        }

        void registerFileAcl(String path, List<FileAclEntry> entries) {
            if (path == null || path.isBlank()) {
                throw new IllegalArgumentException("Filesystem path is required.");
            }

            List<FileAclEntry> safeEntries = List.copyOf(entries);

            for (FileAclEntry entry : safeEntries) {
                if (!identities.containsKey(entry.principalSid())) {
                    throw new IllegalArgumentException(
                        "ACL references an unknown principal."
                    );
                }
            }

            if (fileAcls.putIfAbsent(path, safeEntries) != null) {
                throw new IllegalArgumentException("Duplicate filesystem path.");
            }
        }

        List<AuditFinding> evaluate() {
            List<AuditFinding> findings = new ArrayList<>();

            for (ServiceDefinition service : services.values()) {
                Identity identity = identities.get(service.runAsSid());

                if (service.status() == ServiceStatus.DISABLED
                        && service.automaticStart()) {
                    findings.add(new AuditFinding(
                        Severity.HIGH,
                        service.name(),
                        "Disabled service has automatic startup configured.",
                        "Align service state and startup configuration."
                    ));
                }

                if (service.status() == ServiceStatus.RUNNING
                        && identity.privilegeClass() == PrivilegeClass.ADMINISTRATOR) {
                    findings.add(new AuditFinding(
                        Severity.HIGH,
                        service.name(),
                        "Running service uses an administrator identity.",
                        "Use a least-privilege service identity."
                    ));
                }

                if (service.writableByStandardUsers()) {
                    findings.add(new AuditFinding(
                        Severity.CRITICAL,
                        service.name(),
                        "Standard users can modify the service executable.",
                        "Restrict executable and parent-directory write permissions."
                    ));
                }

                if (service.unquotedPathWithSpaces()) {
                    findings.add(new AuditFinding(
                        Severity.HIGH,
                        service.name(),
                        "Service executable path has spaces and is not quoted.",
                        "Correct the executable path and service configuration."
                    ));
                }

                if (identity.privilegeClass() == PrivilegeClass.SERVICE_IDENTITY
                        && identity.groups().contains("LocalAdministrators")) {
                    findings.add(new AuditFinding(
                        Severity.HIGH,
                        service.name(),
                        "Dedicated service identity has administrator group membership.",
                        "Remove unnecessary group membership."
                    ));
                }
            }

            for (RegistrySetting setting : settings.values()) {
                if (setting.machineWide()) {
                    Identity owner = identities.get(setting.ownerSid());

                    if (owner.privilegeClass() == PrivilegeClass.STANDARD) {
                        findings.add(new AuditFinding(
                            Severity.MEDIUM,
                            setting.keyPath(),
                            "Machine-wide configuration is attributed to a standard user.",
                            "Verify write permissions and assign controlled ownership."
                        ));
                    }
                }
            }

            for (Map.Entry<String, List<FileAclEntry>> entry : fileAcls.entrySet()) {
                for (FileAclEntry acl : entry.getValue()) {
                    if (acl.allowed().contains(FileRight.CHANGE_PERMISSIONS)) {
                        findings.add(new AuditFinding(
                            Severity.MEDIUM,
                            entry.getKey(),
                            "An ACL principal can change permissions.",
                            "Verify that permission administration is intentional."
                        ));
                    }
                }
            }

            findings.sort(
                java.util.Comparator.comparing(AuditFinding::severity)
                    .thenComparing(AuditFinding::resource)
            );

            return List.copyOf(findings);
        }

        Map<String, Identity> identities() {
            return Collections.unmodifiableMap(identities);
        }
    }

    private static final String EMPLOYEE_SID = "S-1-5-21-200-200-200-1001";
    private static final String SERVICE_SID = "S-1-5-21-200-200-200-1002";
    private static final String ADMIN_SID = "S-1-5-21-200-200-200-500";

    private static GovernanceRepository createSampleRepository() {
        GovernanceRepository repository = new GovernanceRepository();

        repository.registerIdentity(new Identity(
            EMPLOYEE_SID,
            "Riya",
            PrivilegeClass.STANDARD,
            true,
            Set.of("Employees", "AuthenticatedUsers")
        ));

        repository.registerIdentity(new Identity(
            SERVICE_SID,
            "InventoryService",
            PrivilegeClass.SERVICE_IDENTITY,
            true,
            Set.of("ServiceAccounts", "LocalAdministrators")
        ));

        repository.registerIdentity(new Identity(
            ADMIN_SID,
            "EndpointAdmin",
            PrivilegeClass.ADMINISTRATOR,
            true,
            Set.of("LocalAdministrators", "AuthenticatedUsers")
        ));

        repository.registerService(new ServiceDefinition(
            "InventoryAgent",
            "C:\\Program Files\\Inventory\\agent.exe",
            SERVICE_SID,
            ServiceStatus.RUNNING,
            true,
            true,
            false
        ));

        repository.registerService(new ServiceDefinition(
            "LegacyUpdater",
            "C:\\Program Files\\Legacy Tools\\update.exe",
            ADMIN_SID,
            ServiceStatus.RUNNING,
            true,
            false,
            true
        ));

        repository.registerService(new ServiceDefinition(
            "DiagnosticAgent",
            "C:\\Windows\\System32\\diagnostic.exe",
            SERVICE_SID,
            ServiceStatus.DISABLED,
            true,
            false,
            false
        ));

        repository.registerRegistrySetting(new RegistrySetting(
            "HKLM\\SOFTWARE\\Contoso\\Inventory",
            "TelemetryEnabled",
            RegistryValueType.DWORD,
            "1",
            ADMIN_SID,
            true
        ));

        repository.registerRegistrySetting(new RegistrySetting(
            "HKCU\\Software\\Contoso\\Inventory",
            "LastWorkspace",
            RegistryValueType.STRING,
            "Operations",
            EMPLOYEE_SID,
            false
        ));

        repository.registerFileAcl(
            "C:\\ProgramData\\Contoso\\Inventory\\settings.json",
            List.of(
                new FileAclEntry(
                    EMPLOYEE_SID,
                    Set.of(FileRight.READ),
                    Set.of(FileRight.WRITE)
                ),
                new FileAclEntry(
                    SERVICE_SID,
                    Set.of(FileRight.READ, FileRight.WRITE),
                    Set.of()
                ),
                new FileAclEntry(
                    ADMIN_SID,
                    Set.of(FileRight.READ, FileRight.CHANGE_PERMISSIONS),
                    Set.of()
                )
            )
        );

        return repository;
    }

    public static void main(String[] args) {
        GovernanceRepository repository = createSampleRepository();

        System.out.println("Managed endpoint identities");
        repository.identities().values().forEach(identity ->
            System.out.printf(
                "%s | %s | %s | enabled=%s | groups=%s%n",
                identity.name(),
                identity.sid(),
                identity.privilegeClass(),
                identity.enabled(),
                identity.groups()
            )
        );

        System.out.println("\nGovernance findings");
        List<AuditFinding> findings = repository.evaluate();

        if (findings.isEmpty()) {
            System.out.println("No policy findings.");
        } else {
            findings.forEach(finding -> System.out.printf(
                "[%s] %s: %s%n  Remediation: %s%n",
                finding.severity(),
                finding.resource(),
                finding.message(),
                finding.remediation()
            ));
        }

        Map<Severity, Long> counts = findings.stream().collect(
            Collectors.groupingBy(
                AuditFinding::severity,
                () -> new java.util.EnumMap<>(Severity.class),
                Collectors.counting()
            )
        );

        System.out.println("\nFinding distribution");
        for (Severity severity : Severity.values()) {
            System.out.printf(
                "%s: %d%n",
                severity,
                counts.getOrDefault(severity, 0L)
            );
        }

        // Invalid machine-wide configuration is rejected before insertion.
        try {
            repository.registerRegistrySetting(new RegistrySetting(
                "HKLM\\SOFTWARE\\Contoso\\Inventory",
                "RetryCount",
                RegistryValueType.DWORD,
                "-1",
                EMPLOYEE_SID,
                true
            ));
        } catch (IllegalArgumentException exception) {
            System.out.println(
                "\nInvalid registry setting rejected: " + exception.getMessage()
            );
        }

        System.out.println(
            "\nModel identifier: " + UUID.randomUUID()
                + ". The model describes policy intent and does not perform "
                + "live Windows administration."
        );
    }
}
