package com.vibecoding.ossaudit.dependency;

import com.vibecoding.ossaudit.core.model.ConfidenceLevel;
import com.vibecoding.ossaudit.core.model.DependencyRecord;
import com.vibecoding.ossaudit.core.model.FileAnalysis;
import com.vibecoding.ossaudit.core.model.Finding;
import com.vibecoding.ossaudit.core.model.FindingStatus;
import com.vibecoding.ossaudit.core.model.Location;
import com.vibecoding.ossaudit.core.model.PatternOccurrence;
import com.vibecoding.ossaudit.core.model.ProjectInventory;
import com.vibecoding.ossaudit.core.model.Severity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Formatter;
import java.util.List;

public class DependencyEngine {
    private final List<KnownVulnerability> knownVulnerabilities = Arrays.asList(
            new KnownVulnerability("org.apache.logging.log4j", "log4j-core", "2.17.1", Severity.CRITICAL,
                    "JAVA-DEP-LOG4J-001", "Known vulnerable log4j-core version",
                    "Public advisory coverage indicates the selected log4j-core version may permit remote code execution.",
                    "Upgrade log4j-core to 2.17.1 or later and review JNDI usage."),
            new KnownVulnerability("com.alibaba", "fastjson", "1.2.83", Severity.HIGH,
                    "JAVA-DEP-FASTJSON-001", "Known vulnerable fastjson version",
                    "Public advisories cover multiple autoType and deserialization issues in older fastjson releases.",
                    "Upgrade fastjson to 1.2.83 or later and disable unsafe autoType behaviors."),
            new KnownVulnerability("commons-collections", "commons-collections", "3.2.2", Severity.HIGH,
                    "JAVA-DEP-COLLECTIONS-001", "Commons Collections gadget exposure",
                    "Older commons-collections releases are frequently present in deserialization exploit chains.",
                    "Upgrade to 3.2.2 or later and remove unsafe deserialization paths.")
    );

    public List<Finding> detect(ProjectInventory inventory, List<FileAnalysis> analyses) {
        List<Finding> findings = new ArrayList<Finding>();
        for (DependencyRecord dependency : inventory.getDependencies()) {
            for (KnownVulnerability vulnerability : knownVulnerabilities) {
                if (vulnerability.matches(dependency) && isVersionLessThan(dependency.getVersion(), vulnerability.fixedVersion)) {
                    findings.add(buildDependencyFinding(inventory, dependency, vulnerability));
                }
            }
        }
        findings.addAll(detectDangerousDependencyUsage(inventory, analyses));
        return findings;
    }

    private List<Finding> detectDangerousDependencyUsage(ProjectInventory inventory, List<FileAnalysis> analyses) {
        List<Finding> findings = new ArrayList<Finding>();
        boolean hasFastjson = hasDependency(inventory, "com.alibaba", "fastjson");
        if (!hasFastjson) {
            return findings;
        }

        for (FileAnalysis analysis : analyses) {
            for (PatternOccurrence source : analysis.getSources()) {
                if (!"REQUEST_BODY".equals(source.getType())) {
                    continue;
                }
                Finding finding = new Finding();
                finding.setFingerprint(fingerprint("JAVA-DEP-FASTJSON-USAGE-001|" + analysis.getFilePath() + "|" + source.getLine()));
                finding.setRuleId("JAVA-DEP-FASTJSON-USAGE-001");
                finding.setTitle("Fastjson request-body parsing should be reviewed");
                finding.setSummary("fastjson is present and this file parses request bodies, which is a common review point for unsafe deserialization.");
                finding.setVulnerabilityType("Unsafe Deserialization");
                finding.setSeverity(Severity.HIGH);
                finding.setConfidence(analysis.isSpringEntryPoint() ? ConfidenceLevel.HIGH_CONFIDENCE : ConfidenceLevel.NEEDS_REVIEW);
                finding.setStatus(FindingStatus.OPEN);
                finding.setSource(source.getSnippet());
                finding.setSink("fastjson dependency usage requires manual sink confirmation");
                finding.setPreconditions("Request-body parsing is present in a repository that depends on fastjson.");
                finding.setReproductionOutline("Review whether attacker-controlled JSON is parsed into unsafe types or autoType is enabled.");
                finding.setAffectedVersions("Dependency version should be checked in the report context.");
                finding.setFixRecommendation("Prefer safe JSON mappings, upgrade fastjson, and avoid unsafe autoType settings.");
                finding.setDependencyContext("com.alibaba:fastjson detected in build metadata.");
                finding.getLocations().add(new Location(analysis.getFilePath().toString(), source.getLine(), source.getSnippet()));
                findings.add(finding);
                break;
            }
        }
        return findings;
    }

    private boolean hasDependency(ProjectInventory inventory, String groupId, String artifactId) {
        for (DependencyRecord dependency : inventory.getDependencies()) {
            if (groupId.equals(dependency.getGroupId()) && artifactId.equals(dependency.getArtifactId())) {
                return true;
            }
        }
        return false;
    }

    private Finding buildDependencyFinding(ProjectInventory inventory, DependencyRecord dependency,
                                           KnownVulnerability vulnerability) {
        Finding finding = new Finding();
        finding.setFingerprint(fingerprint(vulnerability.ruleId + "|" + dependency.getSourceFile() + "|" + dependency.getVersion()));
        finding.setRuleId(vulnerability.ruleId);
        finding.setTitle(vulnerability.title);
        finding.setSummary(vulnerability.summary);
        finding.setVulnerabilityType("Known Vulnerable Dependency");
        finding.setSeverity(vulnerability.severity);
        finding.setConfidence(ConfidenceLevel.CONFIRMED);
        finding.setStatus(FindingStatus.OPEN);
        finding.setSource("Build metadata dependency declaration");
        finding.setSink(dependency.getGroupId() + ":" + dependency.getArtifactId() + ":" + dependency.getVersion());
        finding.setPreconditions("The repository declares a dependency version covered by a public advisory.");
        finding.setReproductionOutline("Confirm the vulnerable dependency is packaged or reachable in the deployment profile.");
        finding.setAffectedVersions(inventory.getProjectVersion());
        finding.setFixRecommendation(vulnerability.fixRecommendation);
        finding.setDependencyContext("Detected in " + dependency.getSourceFile());
        finding.getLocations().add(new Location(dependency.getSourceFile(), 1,
                dependency.getGroupId() + ":" + dependency.getArtifactId() + ":" + dependency.getVersion()));
        return finding;
    }

    private boolean isVersionLessThan(String current, String fixed) {
        if (current == null || current.contains("${") || fixed == null) {
            return false;
        }
        String[] currentParts = current.replaceAll("[^0-9.]", "").split("\\.");
        String[] fixedParts = fixed.replaceAll("[^0-9.]", "").split("\\.");
        int length = Math.max(currentParts.length, fixedParts.length);
        for (int i = 0; i < length; i++) {
            int left = i < currentParts.length && !currentParts[i].isEmpty() ? Integer.parseInt(currentParts[i]) : 0;
            int right = i < fixedParts.length && !fixedParts[i].isEmpty() ? Integer.parseInt(fixedParts[i]) : 0;
            if (left < right) {
                return true;
            }
            if (left > right) {
                return false;
            }
        }
        return false;
    }

    private String fingerprint(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] bytes = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            Formatter formatter = new Formatter();
            for (byte value : bytes) {
                formatter.format("%02x", value);
            }
            String result = formatter.toString();
            formatter.close();
            return result;
        } catch (Exception e) {
            return Integer.toHexString(raw.hashCode());
        }
    }

    private static class KnownVulnerability {
        private final String groupId;
        private final String artifactId;
        private final String fixedVersion;
        private final Severity severity;
        private final String ruleId;
        private final String title;
        private final String summary;
        private final String fixRecommendation;

        private KnownVulnerability(String groupId, String artifactId, String fixedVersion, Severity severity,
                                   String ruleId, String title, String summary, String fixRecommendation) {
            this.groupId = groupId;
            this.artifactId = artifactId;
            this.fixedVersion = fixedVersion;
            this.severity = severity;
            this.ruleId = ruleId;
            this.title = title;
            this.summary = summary;
            this.fixRecommendation = fixRecommendation;
        }

        private boolean matches(DependencyRecord dependency) {
            return groupId.equals(dependency.getGroupId()) && artifactId.equals(dependency.getArtifactId());
        }
    }
}
