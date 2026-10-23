import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/*
 * Enterprise Windows Hardening Governance Model
 *
 * This Java 17 application models an enterprise endpoint-hardening service.
 * Domain types make security policies explicit and prevent accidental mixing
 * of configuration state, policy requirements, and assessment results.
 *
 * The program is assessment-only. It never changes the Windows host.
 */
public class WindowsHardeningGovernance {

    enum Enforcement {
        AUDIT, BLOCK, ALLOW, DISABLED
    }

    enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW
    }

    enum FirewallProfileName {
        DOMAIN, PRIVATE, PUBLIC
    }

    record DefenderPolicy(
            boolean realtimeMonitoring,
            boolean behaviorMonitoring,
            boolean ioavProtection,
            boolean cloudProtection,
            boolean tamperProtection,
            int maximumSignatureAgeHours) {

        DefenderPolicy {
            if (maximumSignatureAgeHours < 0) {
                throw new PolicyException("Signature age cannot be negative");
            }
        }
    }

    record FirewallProfilePolicy(
            FirewallProfileName name,
            boolean enabled,
            boolean blockInboundByDefault,
            boolean allowOutboundByDefault) {
    }

    record SecurityPolicy(
            int minimumPasswordLength,
            int lockoutThreshold,
            int lockoutDurationMinutes,
            boolean auditLogonEvents,
            boolean auditProcessCreation,
            boolean powershellScriptBlockLogging,
            boolean powershellTranscription) {

        SecurityPolicy {
            if (minimumPasswordLength < 1 || minimumPasswordLength > 128) {
                throw new PolicyException("Invalid password minimum");
            }
            if (lockoutThreshold < 1) {
                throw new PolicyException("Lockout threshold must be positive");
            }
            if (lockoutDurationMinutes < 0) {
                throw new PolicyException("Lockout duration cannot be negative");
            }
        }
    }

    record ApplicationControlPolicy(
            Enforcement mode,
            boolean publisherRules,
            boolean pathRules,
            boolean unsignedBinaryBlocking) {
    }

    record AsrPolicy(
            String ruleId,
            String name,
            Enforcement requiredState,
            Severity severity) {

        AsrPolicy {
            Objects.requireNonNull(ruleId);
            Objects.requireNonNull(name);
            Objects.requireNonNull(requiredState);
            Objects.requireNonNull(severity);

            if (!ruleId.matches(
                    "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")) {
                throw new PolicyException("Invalid ASR rule identifier");
            }
        }
    }

    record DefenderState(
            boolean realtimeMonitoring,
            boolean behaviorMonitoring,
            boolean ioavProtection,
            boolean cloudProtection,
            boolean tamperProtection,
            int signatureAgeHours) {
    }

    record FirewallState(
            FirewallProfileName name,
            boolean enabled,
            boolean blockInboundByDefault) {
    }

    record EndpointState(
            String hostname,
            DefenderState defender,
            Map<FirewallProfileName, FirewallState> firewall,
            SecurityPolicy security,
            ApplicationControlPolicy applicationControl,
            Map<String, Enforcement> asrRules) {

        EndpointState {
            Objects.requireNonNull(hostname);
            Objects.requireNonNull(defender);
            Objects.requireNonNull(firewall);
            Objects.requireNonNull(security);
            Objects.requireNonNull(applicationControl);
            Objects.requireNonNull(asrRules);

            if (!Pattern.matches(
                    "[A-Za-z0-9][A-Za-z0-9._-]{0,62}", hostname)) {
                throw new PolicyException("Invalid Windows hostname");
            }
        }
    }

    record Finding(
            String control,
            Severity severity,
            String message,
            String remediation) {
    }

    static final class PolicyException extends RuntimeException {
        PolicyException(String message) {
            super(message);
        }
    }

    interface AssessmentRule {
        void evaluate(EndpointState endpoint, HardeningBaseline baseline,
                      List<Finding> findings);
    }

    record HardeningBaseline(
            DefenderPolicy defender,
            Map<FirewallProfileName, FirewallProfilePolicy> firewall,
            SecurityPolicy security,
            ApplicationControlPolicy applicationControl,
            List<AsrPolicy> asrRules) {

        HardeningBaseline {
            Objects.requireNonNull(defender);
            Objects.requireNonNull(firewall);
            Objects.requireNonNull(security);
            Objects.requireNonNull(applicationControl);
            Objects.requireNonNull(asrRules);

            for (FirewallProfileName name : FirewallProfileName.values()) {
                if (!firewall.containsKey(name)) {
                    throw new PolicyException(
                            "Baseline must contain " + name + " firewall policy");
                }
            }

            if (applicationControl.mode() != Enforcement.BLOCK) {
                throw new PolicyException(
                        "Enterprise application control must use BLOCK mode");
            }
        }
    }

    static final class DefenderAssessmentRule implements AssessmentRule {
        @Override
        public void evaluate(
                EndpointState endpoint,
                HardeningBaseline baseline,
                List<Finding> findings) {

            DefenderState actual = endpoint.defender();
            DefenderPolicy expected = baseline.defender();

            check(
                    actual.realtimeMonitoring(),
                    expected.realtimeMonitoring(),
                    findings,
                    "Real-time monitoring",
                    Severity.CRITICAL);

            check(
                    actual.behaviorMonitoring(),
                    expected.behaviorMonitoring(),
                    findings,
                    "Behavior monitoring",
                    Severity.HIGH);

            check(
                    actual.ioavProtection(),
                    expected.ioavProtection(),
                    findings,
                    "IOAV protection",
                    Severity.HIGH);

            check(
                    actual.cloudProtection(),
                    expected.cloudProtection(),
                    findings,
                    "Cloud protection",
                    Severity.HIGH);

            check(
                    actual.tamperProtection(),
                    expected.tamperProtection(),
                    findings,
                    "Tamper protection",
                    Severity.CRITICAL);

            if (actual.signatureAgeHours() >
                    expected.maximumSignatureAgeHours()) {
                findings.add(new Finding(
                        "Microsoft Defender",
                        Severity.HIGH,
                        "Security intelligence is older than the baseline",
                        "Update Defender security intelligence"));
            }
        }

        private static void check(
                boolean actual,
                boolean expected,
                List<Finding> findings,
                String name,
                Severity severity) {

            if (expected && !actual) {
                findings.add(new Finding(
                        "Microsoft Defender",
                        severity,
                        name + " is disabled",
                        "Enable " + name));
            }
        }
    }

    static final class FirewallAssessmentRule implements AssessmentRule {
        @Override
        public void evaluate(
                EndpointState endpoint,
                HardeningBaseline baseline,
                List<Finding> findings) {

            for (FirewallProfileName name : FirewallProfileName.values()) {
                FirewallState actual = endpoint.firewall().get(name);
                FirewallProfilePolicy expected = baseline.firewall().get(name);

                if (actual == null) {
                    findings.add(new Finding(
                            "Windows Firewall",
                            Severity.CRITICAL,
                            name + " firewall telemetry is missing",
                            "Collect the profile state"));
                    continue;
                }

                if (expected.enabled() && !actual.enabled()) {
                    findings.add(new Finding(
                            "Windows Firewall",
                            name == FirewallProfileName.PUBLIC
                                    ? Severity.CRITICAL
                                    : Severity.HIGH,
                            name + " firewall profile is disabled",
                            "Enable the " + name + " firewall profile"));
                }

                if (expected.blockInboundByDefault()
                        && !actual.blockInboundByDefault()) {
                    findings.add(new Finding(
                            "Windows Firewall",
                            Severity.HIGH,
                            name + " allows inbound traffic by default",
                            "Set the inbound default action to Block"));
                }
            }
        }
    }

    static final class SecurityAssessmentRule implements AssessmentRule {
        @Override
        public void evaluate(
                EndpointState endpoint,
                HardeningBaseline baseline,
                List<Finding> findings) {

            SecurityPolicy actual = endpoint.security();
            SecurityPolicy expected = baseline.security();

            if (actual.minimumPasswordLength()
                    < expected.minimumPasswordLength()) {
                findings.add(new Finding(
                        "Security Policy",
                        Severity.MEDIUM,
                        "Password minimum is below the enterprise baseline",
                        "Increase the password minimum"));
            }

            if (actual.lockoutThreshold() > expected.lockoutThreshold()) {
                findings.add(new Finding(
                        "Security Policy",
                        Severity.MEDIUM,
                        "Account lockout threshold is too permissive",
                        "Reduce the lockout threshold"));
            }

            auditCheck(
                    actual.auditLogonEvents(),
                    expected.auditLogonEvents(),
                    findings,
                    "Logon auditing",
                    Severity.MEDIUM);

            auditCheck(
                    actual.auditProcessCreation(),
                    expected.auditProcessCreation(),
                    findings,
                    "Process creation auditing",
                    Severity.MEDIUM);

            auditCheck(
                    actual.powershellScriptBlockLogging(),
                    expected.powershellScriptBlockLogging(),
                    findings,
                    "PowerShell script block logging",
                    Severity.HIGH);

            auditCheck(
                    actual.powershellTranscription(),
                    expected.powershellTranscription(),
                    findings,
                    "PowerShell transcription",
                    Severity.HIGH);
        }

        private static void auditCheck(
                boolean actual,
                boolean expected,
                List<Finding> findings,
                String name,
                Severity severity) {

            if (expected && !actual) {
                findings.add(new Finding(
                        "Security Policy",
                        severity,
                        name + " is disabled",
                        "Enable " + name));
            }
        }
    }

    static final class ApplicationControlAssessmentRule
            implements AssessmentRule {

        @Override
        public void evaluate(
                EndpointState endpoint,
                HardeningBaseline baseline,
                List<Finding> findings) {

            ApplicationControlPolicy actual =
                    endpoint.applicationControl();
            ApplicationControlPolicy expected =
                    baseline.applicationControl();

            if (actual.mode() != expected.mode()) {
                findings.add(new Finding(
                        "Application Control",
                        Severity.HIGH,
                        "Application control is operating in "
                                + actual.mode() + " mode",
                        "Move application control to "
                                + expected.mode() + " mode"));
            }

            if (expected.publisherRules() && !actual.publisherRules()) {
                findings.add(new Finding(
                        "Application Control",
                        Severity.HIGH,
                        "Publisher rules are disabled",
                        "Enable publisher rules"));
            }

            if (expected.pathRules() && !actual.pathRules()) {
                findings.add(new Finding(
                        "Application Control",
                        Severity.HIGH,
                        "Path rules are disabled",
                        "Enable path rules"));
            }

            if (expected.unsignedBinaryBlocking()
                    && !actual.unsignedBinaryBlocking()) {
                findings.add(new Finding(
                        "Application Control",
                        Severity.HIGH,
                        "Unsigned binary blocking is disabled",
                        "Block unsigned executable content"));
            }
        }
    }

    static final class AsrAssessmentRule implements AssessmentRule {
        @Override
        public void evaluate(
                EndpointState endpoint,
                HardeningBaseline baseline,
                List<Finding> findings) {

            for (AsrPolicy policy : baseline.asrRules()) {
                Enforcement actual = endpoint.asrRules()
                        .getOrDefault(policy.ruleId(), Enforcement.DISABLED);

                if (actual != policy.requiredState()) {
                    findings.add(new Finding(
                            "Attack Surface Reduction",
                            policy.severity(),
                            policy.name() + " is " + actual
                                    + "; baseline requires "
                                    + policy.requiredState(),
                            "Set ASR rule " + policy.ruleId()
                                    + " to " + policy.requiredState()));
                }
            }
        }
    }

    static final class HardeningAssessmentService {
        private final List<AssessmentRule> rules;

        HardeningAssessmentService(List<AssessmentRule> rules) {
            this.rules = List.copyOf(rules);
        }

        List<Finding> assess(
                EndpointState endpoint,
                HardeningBaseline baseline) {

            List<Finding> findings = new ArrayList<>();

            for (AssessmentRule rule : rules) {
                rule.evaluate(endpoint, baseline, findings);
            }

            return List.copyOf(findings);
        }
    }

    static HardeningBaseline baseline() {
        DefenderPolicy defender = new DefenderPolicy(
                true,
                true,
                true,
                true,
                true,
                24);

        Map<FirewallProfileName, FirewallProfilePolicy> firewall =
                Map.of(
                        FirewallProfileName.DOMAIN,
                        new FirewallProfilePolicy(
                                FirewallProfileName.DOMAIN,
                                true,
                                true,
                                true),
                        FirewallProfileName.PRIVATE,
                        new FirewallProfilePolicy(
                                FirewallProfileName.PRIVATE,
                                true,
                                true,
                                true),
                        FirewallProfileName.PUBLIC,
                        new FirewallProfilePolicy(
                                FirewallProfileName.PUBLIC,
                                true,
                                true,
                                true));

        SecurityPolicy security = new SecurityPolicy(
                14,
                5,
                15,
                true,
                true,
                true,
                true);

        ApplicationControlPolicy applicationControl =
                new ApplicationControlPolicy(
                        Enforcement.BLOCK,
                        true,
                        true,
                        true);

        List<AsrPolicy> asr = List.of(
                new AsrPolicy(
                        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
                        "Block executable content from email client and webmail",
                        Enforcement.BLOCK,
                        Severity.HIGH),
                new AsrPolicy(
                        "3b576869-a4ec-4529-8536-b80a7769e899",
                        "Block Office applications from creating executable content",
                        Enforcement.BLOCK,
                        Severity.HIGH),
                new AsrPolicy(
                        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
                        "Block Office applications from injecting code into other processes",
                        Enforcement.BLOCK,
                        Severity.HIGH),
                new AsrPolicy(
                        "26190899-1602-49e8-8b27-eb1d0a1ce869",
                        "Block Office communication applications from creating child processes",
                        Enforcement.AUDIT,
                        Severity.MEDIUM));

        return new HardeningBaseline(
                defender,
                firewall,
                security,
                applicationControl,
                asr);
    }

    static EndpointState endpoint() {
        DefenderState defender = new DefenderState(
                true,
                false,
                true,
                true,
                false,
                41);

        Map<FirewallProfileName, FirewallState> firewall =
                new EnumMap<>(FirewallProfileName.class);

        firewall.put(
                FirewallProfileName.DOMAIN,
                new FirewallState(
                        FirewallProfileName.DOMAIN,
                        true,
                        true));

        firewall.put(
                FirewallProfileName.PRIVATE,
                new FirewallState(
                        FirewallProfileName.PRIVATE,
                        true,
                        true));

        firewall.put(
                FirewallProfileName.PUBLIC,
                new FirewallState(
                        FirewallProfileName.PUBLIC,
                        false,
                        false));

        SecurityPolicy security = new SecurityPolicy(
                11,
                10,
                10,
                true,
                false,
                true,
                false);

        ApplicationControlPolicy applicationControl =
                new ApplicationControlPolicy(
                        Enforcement.AUDIT,
                        true,
                        false,
                        false);

        Map<String, Enforcement> asr = new HashMap<>();
        asr.put(
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
                Enforcement.BLOCK);
        asr.put(
                "3b576869-a4ec-4529-8536-b80a7769e899",
                Enforcement.AUDIT);
        asr.put(
                "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
                Enforcement.BLOCK);

        return new EndpointState(
                "WIN-OPS-311",
                defender,
                Map.copyOf(firewall),
                security,
                applicationControl,
                Map.copyOf(asr));
    }

    static void printReport(List<Finding> findings) {
        Map<Severity, Long> counts = new EnumMap<>(Severity.class);

        for (Finding finding : findings) {
            counts.merge(finding.severity(), 1L, Long::sum);
        }

        System.out.println("Windows Hardening Governance Assessment");
        System.out.println("=======================================");
        System.out.println("Findings: " + findings.size());

        for (Severity severity : Severity.values()) {
            System.out.printf(
                    "%-10s %d%n",
                    severity,
                    counts.getOrDefault(severity, 0L));
        }

        System.out.println("\nDetailed findings:");

        findings.forEach(finding -> {
            System.out.println(
                    "[" + finding.severity() + "] "
                            + finding.control());
            System.out.println("  " + finding.message());
            System.out.println("  Remediation: " + finding.remediation());
        });
    }

    public static void main(String[] args) {
        try {
            HardeningBaseline baseline = baseline();

            HardeningAssessmentService service =
                    new HardeningAssessmentService(List.of(
                            new DefenderAssessmentRule(),
                            new FirewallAssessmentRule(),
                            new SecurityAssessmentRule(),
                            new ApplicationControlAssessmentRule(),
                            new AsrAssessmentRule()));

            EndpointState endpoint = endpoint();

            List<Finding> findings =
                    service.assess(endpoint, baseline);

            System.out.println("Endpoint: " + endpoint.hostname());
            printReport(findings);

            System.out.println(
                    "\nAssessment-only execution: no Windows settings were changed.");
        } catch (PolicyException exception) {
            System.err.println("Policy validation failed: "
                    + exception.getMessage());
            System.exit(1);
        }
    }
}
