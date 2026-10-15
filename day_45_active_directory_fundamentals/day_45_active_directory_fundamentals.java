import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/*
 * Enterprise Active Directory governance model.
 *
 * The domain layer owns directory identity and membership. Policy evaluation
 * is separate from authentication and resource authorization, preventing
 * organizational placement from being confused with access rights.
 *
 * Requires Java 17 or later. This is an in-memory educational model.
 */
public class ActiveDirectoryEnterprise {
    enum AccountStatus {
        ENABLED, DISABLED, LOCKED
    }

    enum GroupScope {
        GLOBAL, DOMAIN_LOCAL, UNIVERSAL
    }

    enum GroupType {
        SECURITY, DISTRIBUTION
    }

    enum PolicySetting {
        PASSWORD_MIN_LENGTH,
        LOCKOUT_THRESHOLD,
        REQUIRE_MFA,
        USB_STORAGE_ALLOWED,
        SCREEN_LOCK_MINUTES,
        FIREWALL_ENABLED
    }

    static class DirectoryException extends RuntimeException {
        DirectoryException(String message) {
            super(message);
        }
    }

    static class ValidationException extends DirectoryException {
        ValidationException(String message) {
            super(message);
        }
    }

    static class MissingObjectException extends DirectoryException {
        MissingObjectException(String message) {
            super(message);
        }
    }

    static class AccessDeniedException extends DirectoryException {
        AccessDeniedException(String message) {
            super(message);
        }
    }

    abstract static class DirectoryObject {
        private final UUID id = UUID.randomUUID();
        private final String name;
        private final String distinguishedName;
        private final Instant createdAt = Instant.now();
        private boolean enabled = true;

        DirectoryObject(String name, String distinguishedName) {
            this.name = requireText(name, "Object name");
            this.distinguishedName = requireText(
                distinguishedName, "Distinguished name"
            );
        }

        UUID id() {
            return id;
        }

        String name() {
            return name;
        }

        String distinguishedName() {
            return distinguishedName;
        }

        Instant createdAt() {
            return createdAt;
        }

        boolean enabled() {
            return enabled;
        }

        void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    static final class User extends DirectoryObject {
        private final String samAccountName;
        private final String userPrincipalName;
        private final String department;
        private final Set<UUID> directGroupIds = new LinkedHashSet<>();
        private AccountStatus status = AccountStatus.ENABLED;
        private boolean mfaRegistered;

        User(
            String name,
            String samAccountName,
            String userPrincipalName,
            String department,
            String distinguishedName
        ) {
            super(name, distinguishedName);
            this.samAccountName = samAccountName;
            this.userPrincipalName = userPrincipalName;
            this.department = department;
        }

        String samAccountName() {
            return samAccountName;
        }

        String userPrincipalName() {
            return userPrincipalName;
        }

        String department() {
            return department;
        }

        AccountStatus status() {
            return status;
        }

        void setStatus(AccountStatus status) {
            this.status = Objects.requireNonNull(status);
            setEnabled(status == AccountStatus.ENABLED);
        }

        boolean mfaRegistered() {
            return mfaRegistered;
        }

        void setMfaRegistered(boolean value) {
            mfaRegistered = value;
        }
    }

    static final class SecurityGroup extends DirectoryObject {
        private final GroupScope scope;
        private final GroupType type;
        private final Set<UUID> memberIds = new LinkedHashSet<>();

        SecurityGroup(
            String name,
            String dn,
            GroupScope scope,
            GroupType type
        ) {
            super(name, dn);
            this.scope = Objects.requireNonNull(scope);
            this.type = Objects.requireNonNull(type);
        }

        GroupScope scope() {
            return scope;
        }

        GroupType type() {
            return type;
        }
    }

    static final class OrganizationalUnit extends DirectoryObject {
        private final UUID parentId;
        private final boolean protectedFromDeletion;
        private final Set<UUID> childIds = new LinkedHashSet<>();
        private boolean blockInheritance;

        OrganizationalUnit(
            String name,
            String dn,
            UUID parentId,
            boolean protectedFromDeletion
        ) {
            super(name, dn);
            this.parentId = parentId;
            this.protectedFromDeletion = protectedFromDeletion;
        }

        UUID parentId() {
            return parentId;
        }

        boolean protectedFromDeletion() {
            return protectedFromDeletion;
        }

        boolean blockInheritance() {
            return blockInheritance;
        }

        void setBlockInheritance(boolean value) {
            blockInheritance = value;
        }
    }

    static final class DomainController {
        private final String name;
        private final String site;
        private final Set<String> operationsMasterRoles;
        private final boolean writable;
        private final boolean globalCatalog;
        private long observedRevision;
        private boolean reachable = true;

        DomainController(
            String name,
            String site,
            Set<String> operationsMasterRoles,
            boolean writable,
            boolean globalCatalog
        ) {
            this.name = requireText(name, "Controller name");
            this.site = requireText(site, "Controller site");
            this.operationsMasterRoles = Set.copyOf(operationsMasterRoles);
            this.writable = writable;
            this.globalCatalog = globalCatalog;
        }

        String name() {
            return name;
        }

        String site() {
            return site;
        }

        long observedRevision() {
            return observedRevision;
        }

        void setObservedRevision(long revision) {
            observedRevision = revision;
        }

        boolean reachable() {
            return reachable;
        }

        void setReachable(boolean reachable) {
            this.reachable = reachable;
        }
    }

    static final class GroupPolicy {
        private final UUID id = UUID.randomUUID();
        private final String name;
        private final EnumMap<PolicySetting, Object> settings =
            new EnumMap<>(PolicySetting.class);
        private boolean enabled = true;
        private boolean computerConfigurationEnabled = true;

        GroupPolicy(String name, Map<PolicySetting, Object> settings) {
            this.name = requireText(name, "GPO name");
            settings.forEach((setting, value) -> {
                validateSetting(setting, value);
                this.settings.put(setting, value);
            });
        }
    }

    static final class PolicyLink {
        private final UUID policyId;
        private final UUID targetOuId;
        private final int order;
        private final boolean enforced;
        private boolean disabled;

        PolicyLink(
            UUID policyId,
            UUID targetOuId,
            int order,
            boolean enforced
        ) {
            this.policyId = Objects.requireNonNull(policyId);
            this.targetOuId = Objects.requireNonNull(targetOuId);
            if (order < 1) throw new ValidationException("Link order must be positive.");
            this.order = order;
            this.enforced = enforced;
        }
    }

    record AuditEvent(long revision, Instant time, String action, String subject) {}

    record ControllerStatus(
        String name,
        String site,
        boolean reachable,
        long observedRevision,
        long currentRevision,
        long lag
    ) {}

    static final class DirectoryService {
        private static final Pattern SAM_PATTERN =
            Pattern.compile("[A-Za-z0-9._-]{1,20}");

        private final String dnsName;
        private final String netbiosName;
        private final String domainDn;
        private long revision;

        private final Map<UUID, DirectoryObject> objects = new LinkedHashMap<>();
        private final Map<String, UUID> samIndex = new HashMap<>();
        private final Map<UUID, SecurityGroup> groups = new LinkedHashMap<>();
        private final Map<UUID, OrganizationalUnit> ous = new LinkedHashMap<>();
        private final Map<String, UUID> dnIndex = new HashMap<>();
        private final Map<String, DomainController> controllers = new LinkedHashMap<>();
        private final Map<UUID, GroupPolicy> policies = new LinkedHashMap<>();
        private final List<PolicyLink> policyLinks = new ArrayList<>();
        private final List<AuditEvent> audit = new ArrayList<>();
        private final OrganizationalUnit root;

        DirectoryService(String dnsName, String netbiosName) {
            this.dnsName = dnsName.trim().toLowerCase(Locale.ROOT);
            this.netbiosName = netbiosName.trim().toUpperCase(Locale.ROOT);

            if (!this.dnsName.matches(
                "(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+" +
                "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            )) {
                throw new ValidationException("Invalid domain DNS name.");
            }
            if (!this.netbiosName.matches("[A-Z0-9-]{1,15}")) {
                throw new ValidationException("Invalid NetBIOS domain name.");
            }

            String[] labels = this.dnsName.split("\\.");
            List<String> dcLabels = new ArrayList<>();
            for (String label : labels) dcLabels.add("DC=" + label);
            domainDn = String.join(",", dcLabels);

            root = new OrganizationalUnit("Domain Root", domainDn, null, true);
            ous.put(root.id(), root);
            objects.put(root.id(), root);
            dnIndex.put(normalizeDn(domainDn), root.id());
        }

        private static String normalizeDn(String dn) {
            return dn.toLowerCase(Locale.ROOT);
        }

        private static String requireText(String value, String label) {
            if (value == null || value.isBlank()) {
                throw new ValidationException(label + " cannot be blank.");
            }
            return value.trim();
        }

        private void record(String action, String subject) {
            audit.add(new AuditEvent(++revision, Instant.now(), action, subject));
        }

        String domainDn() {
            return domainDn;
        }

        void addController(DomainController controller) {
            String key = controller.name().toLowerCase(Locale.ROOT);
            if (controllers.putIfAbsent(key, controller) != null) {
                throw new ValidationException("Duplicate domain controller.");
            }
            record("controller-added", controller.name());
        }

        OrganizationalUnit createOU(
            String name,
            UUID parentId,
            boolean protectFromDeletion
        ) {
            OrganizationalUnit parent = ous.get(parentId);
            if (parent == null) throw new MissingObjectException("Parent OU not found.");

            String safeName = requireText(name, "OU name");
            if (safeName.contains(",") || safeName.contains("=")) {
                throw new ValidationException("OU name contains a DN delimiter.");
            }

            String dn = "OU=" + safeName + "," + parent.distinguishedName();
            if (dnIndex.containsKey(normalizeDn(dn))) {
                throw new ValidationException("Distinguished name already exists.");
            }

            OrganizationalUnit ou = new OrganizationalUnit(
                safeName, dn, parentId, protectFromDeletion
            );
            ous.put(ou.id(), ou);
            objects.put(ou.id(), ou);
            dnIndex.put(normalizeDn(dn), ou.id());
            parent.childIds.add(ou.id());
            record("ou-created", dn);
            return ou;
        }

        User createUser(
            String displayName,
            String samAccountName,
            String department,
            UUID ouId
        ) {
            String name = requireText(displayName, "Display name");
            String sam = requireText(samAccountName, "sAMAccountName");
            String dept = requireText(department, "Department");

            if (!SAM_PATTERN.matcher(sam).matches()) {
                throw new ValidationException("Invalid sAMAccountName.");
            }

            String key = sam.toLowerCase(Locale.ROOT);
            if (samIndex.containsKey(key)) {
                throw new ValidationException("sAMAccountName already exists.");
            }

            OrganizationalUnit ou = ous.get(ouId);
            if (ou == null) throw new MissingObjectException("Target OU not found.");

            String dn = "CN=" + name + "," + ou.distinguishedName();
            if (dnIndex.containsKey(normalizeDn(dn))) {
                throw new ValidationException("Distinguished name already exists.");
            }

            User user = new User(
                name, sam, sam + "@" + dnsName, dept, dn
            );
            objects.put(user.id(), user);
            samIndex.put(key, user.id());
            dnIndex.put(normalizeDn(dn), user.id());
            record("user-created", sam);
            return user;
        }

        SecurityGroup createGroup(
            String name,
            UUID ouId,
            GroupScope scope,
            GroupType type
        ) {
            OrganizationalUnit ou = ous.get(ouId);
            if (ou == null) throw new MissingObjectException("Group OU not found.");

            String dn = "CN=" + requireText(name, "Group name") + "," +
                        ou.distinguishedName();
            if (dnIndex.containsKey(normalizeDn(dn))) {
                throw new ValidationException("Group distinguished name already exists.");
            }

            SecurityGroup group = new SecurityGroup(name, dn, scope, type);
            groups.put(group.id(), group);
            objects.put(group.id(), group);
            dnIndex.put(normalizeDn(dn), group.id());
            record("group-created", group.name());
            return group;
        }

        void addMember(UUID groupId, UUID memberId) {
            SecurityGroup group = groups.get(groupId);
            DirectoryObject member = objects.get(memberId);

            if (group == null || member == null) {
                throw new MissingObjectException("Group or member not found.");
            }
            if (group.type() != GroupType.SECURITY) {
                throw new ValidationException("Distribution groups cannot grant access.");
            }
            if (groupId.equals(memberId)) {
                throw new ValidationException("Self-membership is forbidden.");
            }

            if (member instanceof SecurityGroup) {
                Set<UUID> visited = new HashSet<>();
                if (containsGroup(memberId, groupId, visited)) {
                    throw new ValidationException("Nested membership cycle detected.");
                }
            }

            group.memberIds.add(memberId);
            record("group-member-added", group.name() + ":" + member.name());
        }

        private boolean containsGroup(UUID start, UUID target, Set<UUID> visited) {
            if (start.equals(target)) return true;
            if (!visited.add(start)) return false;
            SecurityGroup group = groups.get(start);
            if (group == null) return false;

            for (UUID memberId : group.memberIds) {
                if (groups.containsKey(memberId) &&
                    containsGroup(memberId, target, visited)) {
                    return true;
                }
            }
            return false;
        }

        Set<UUID> effectiveGroups(UUID principalId) {
            if (!objects.containsKey(principalId)) {
                throw new MissingObjectException("Principal not found.");
            }

            Set<UUID> result = new LinkedHashSet<>();
            Set<UUID> visited = new HashSet<>();
            Deque<UUID> pending = new ArrayDeque<>();
            pending.push(principalId);

            while (!pending.isEmpty()) {
                UUID current = pending.pop();
                if (!visited.add(current)) continue;

                for (SecurityGroup group : groups.values()) {
                    if (group.enabled() && group.memberIds.contains(current)) {
                        if (result.add(group.id())) pending.push(group.id());
                    }
                }
            }
            return Collections.unmodifiableSet(result);
        }

        void registerPolicy(GroupPolicy policy) {
            if (policies.putIfAbsent(policy.id, policy) != null) {
                throw new ValidationException("Duplicate policy identifier.");
            }
            record("gpo-registered", policy.name);
        }

        void linkPolicy(
            UUID policyId,
            UUID targetOuId,
            int order,
            boolean enforced
        ) {
            if (!policies.containsKey(policyId)) {
                throw new MissingObjectException("GPO not found.");
            }
            if (!ous.containsKey(targetOuId)) {
                throw new MissingObjectException("Policy target OU not found.");
            }

            policyLinks.add(new PolicyLink(policyId, targetOuId, order, enforced));
            record("gpo-linked", policies.get(policyId).name);
        }

        Map<PolicySetting, Object> effectiveComputerPolicy(UUID targetOuId) {
            List<OrganizationalUnit> chain = new ArrayList<>();
            OrganizationalUnit current = ous.get(targetOuId);
            if (current == null) throw new MissingObjectException("Target OU not found.");

            while (current != null) {
                chain.add(0, current);
                current = current.parentId() == null ? null : ous.get(current.parentId());
            }

            EnumMap<PolicySetting, Object> result =
                new EnumMap<>(PolicySetting.class);
            EnumMap<PolicySetting, Object> enforced =
                new EnumMap<>(PolicySetting.class);

            for (OrganizationalUnit ou : chain) {
                List<PolicyLink> scoped = policyLinks.stream()
                    .filter(link -> !link.disabled && link.targetOuId.equals(ou.id()))
                    .sorted((a, b) -> Integer.compare(b.order, a.order))
                    .toList();

                for (PolicyLink link : scoped) {
                    GroupPolicy policy = policies.get(link.policyId);
                    if (policy == null || !policy.enabled ||
                        !policy.computerConfigurationEnabled) continue;

                    for (var entry : policy.settings.entrySet()) {
                        if (link.enforced) {
                            enforced.put(entry.getKey(), entry.getValue());
                        } else if (!enforced.containsKey(entry.getKey())) {
                            result.put(entry.getKey(), entry.getValue());
                        }
                    }
                }
            }

            result.putAll(enforced);
            return Collections.unmodifiableMap(result);
        }

        void authorize(UUID principalId, UUID requiredGroupId) {
            DirectoryObject principal = objects.get(principalId);
            if (principal == null) throw new MissingObjectException("Principal not found.");
            if (!principal.enabled()) throw new AccessDeniedException("Principal disabled.");
            if (!groups.containsKey(requiredGroupId)) {
                throw new MissingObjectException("Required group not found.");
            }
            if (!effectiveGroups(principalId).contains(requiredGroupId)) {
                throw new AccessDeniedException("Required security group membership absent.");
            }
            record("access-granted", principal.name());
        }

        List<ControllerStatus> replicationStatus() {
            List<ControllerStatus> result = new ArrayList<>();
            for (DomainController dc : controllers.values()) {
                result.add(new ControllerStatus(
                    dc.name(),
                    dc.site(),
                    dc.reachable(),
                    dc.observedRevision(),
                    revision,
                    Math.max(0, revision - dc.observedRevision())
                ));
            }
            return List.copyOf(result);
        }

        List<AuditEvent> auditEvents() {
            return List.copyOf(audit);
        }
    }

    private static void validateSetting(PolicySetting setting, Object value) {
        Objects.requireNonNull(setting, "Policy setting");
        Objects.requireNonNull(value, "Policy value");

        switch (setting) {
            case PASSWORD_MIN_LENGTH -> {
                if (!(value instanceof Integer number) || number < 8 || number > 128) {
                    throw new ValidationException("Password minimum length must be 8-128.");
                }
            }
            case LOCKOUT_THRESHOLD -> {
                if (!(value instanceof Integer number) || number < 0 || number > 20) {
                    throw new ValidationException("Lockout threshold must be 0-20.");
                }
            }
            case SCREEN_LOCK_MINUTES -> {
                if (!(value instanceof Integer number) || number < 1 || number > 240) {
                    throw new ValidationException("Screen lock must be 1-240 minutes.");
                }
            }
            case REQUIRE_MFA, USB_STORAGE_ALLOWED, FIREWALL_ENABLED -> {
                if (!(value instanceof Boolean)) {
                    throw new ValidationException("Boolean policy requires a Boolean value.");
                }
            }
        }
    }

    public static void main(String[] args) {
        DirectoryService directory = new DirectoryService(
            "corp.example.com", "CORP"
        );

        DomainController dc01 = new DomainController(
            "DC01", "Lucknow", Set.of("PDC Emulator", "RID Master"), true, true
        );
        DomainController dc02 = new DomainController(
            "DC02", "Delhi", Set.of(), true, true
        );
        directory.addController(dc01);
        directory.addController(dc02);

        OrganizationalUnit engineering = directory.createOU(
            "Engineering", directory.root.id(), true
        );
        OrganizationalUnit privileged = directory.createOU(
            "Privileged", engineering.id(), true
        );

        User developer = directory.createUser(
            "Riya Sharma", "riya.sharma", "Engineering", engineering.id()
        );
        User operator = directory.createUser(
            "Release Operator", "release.operator", "IT", privileged.id()
        );
        developer.setMfaRegistered(true);
        operator.setMfaRegistered(true);

        SecurityGroup developers = directory.createGroup(
            "Engineering-Developers",
            engineering.id(),
            GroupScope.GLOBAL,
            GroupType.SECURITY
        );
        SecurityGroup productionAdmins = directory.createGroup(
            "Production-Administrators",
            privileged.id(),
            GroupScope.DOMAIN_LOCAL,
            GroupType.SECURITY
        );

        directory.addMember(developers.id(), developer.id());
        directory.addMember(productionAdmins.id(), operator.id());
        directory.addMember(productionAdmins.id(), developers.id());

        System.out.println("Domain DN: " + directory.domainDn());
        System.out.println("Developer DN: " + developer.distinguishedName());
        System.out.println("Developer effective groups: " +
            directory.effectiveGroups(developer.id()).size());

        try {
            directory.authorize(developer.id(), productionAdmins.id());
        } catch (AccessDeniedException ex) {
            System.out.println("Developer production access denied: " + ex.getMessage());
        }

        directory.authorize(operator.id(), productionAdmins.id());
        System.out.println("Release operator production access granted.");

        EnumMap<PolicySetting, Object> baselineSettings =
            new EnumMap<>(PolicySetting.class);
        baselineSettings.put(PolicySetting.PASSWORD_MIN_LENGTH, 14);
        baselineSettings.put(PolicySetting.LOCKOUT_THRESHOLD, 5);
        baselineSettings.put(PolicySetting.REQUIRE_MFA, true);
        baselineSettings.put(PolicySetting.USB_STORAGE_ALLOWED, false);
        baselineSettings.put(PolicySetting.SCREEN_LOCK_MINUTES, 10);
        baselineSettings.put(PolicySetting.FIREWALL_ENABLED, true);

        GroupPolicy baseline = new GroupPolicy(
            "Corporate Security Baseline", baselineSettings
        );
        directory.registerPolicy(baseline);
        directory.linkPolicy(baseline.id, directory.root.id(), 1, true);

        EnumMap<PolicySetting, Object> engineeringSettings =
            new EnumMap<>(PolicySetting.class);
        engineeringSettings.put(PolicySetting.USB_STORAGE_ALLOWED, true);
        engineeringSettings.put(PolicySetting.SCREEN_LOCK_MINUTES, 20);

        GroupPolicy workstationPolicy = new GroupPolicy(
            "Engineering Workstations", engineeringSettings
        );
        directory.registerPolicy(workstationPolicy);
        directory.linkPolicy(workstationPolicy.id, engineering.id(), 1, false);

        System.out.println("\nEffective engineering computer policy:");
        directory.effectiveComputerPolicy(engineering.id()).forEach(
            (setting, value) -> System.out.println("  " + setting + " = " + value)
        );

        try {
            directory.addMember(developers.id(), productionAdmins.id());
        } catch (ValidationException ex) {
            System.out.println("\nCircular group nesting rejected: " + ex.getMessage());
        }

        try {
            new GroupPolicy(
                "Invalid Policy",
                Map.of(PolicySetting.PASSWORD_MIN_LENGTH, 4)
            );
        } catch (ValidationException ex) {
            System.out.println("Invalid GPO setting rejected: " + ex.getMessage());
        }

        dc01.setObservedRevision(directory.auditEvents().size());
        dc02.setObservedRevision(Math.max(0, directory.auditEvents().size() - 3));

        System.out.println("\nDomain controller replication observations:");
        for (ControllerStatus status : directory.replicationStatus()) {
            System.out.printf(
                Locale.ROOT,
                "  %s site=%s reachable=%s revision-lag=%d%n",
                status.name(), status.site(), status.reachable(), status.lag()
            );
        }

        System.out.println("\nRecorded directory events: " + directory.auditEvents().size());
    }
}
