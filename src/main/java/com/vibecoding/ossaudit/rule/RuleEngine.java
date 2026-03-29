package com.vibecoding.ossaudit.rule;

import com.vibecoding.ossaudit.core.model.ConfidenceLevel;
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
import java.util.Formatter;
import java.util.List;

public class RuleEngine {

    public List<Finding> detect(ProjectInventory inventory, List<FileAnalysis> analyses) {
        List<Finding> findings = new ArrayList<Finding>();
        for (FileAnalysis analysis : analyses) {
            boolean hasSources = !analysis.getSources().isEmpty();
            boolean hasEntryPoint = analysis.isSpringEntryPoint() || analysis.isServletEntryPoint();
            for (PatternOccurrence sink : analysis.getSinks()) {
                findings.add(buildFinding(inventory, analysis, sink, hasSources, hasEntryPoint));
            }
        }
        return findings;
    }

    private Finding buildFinding(ProjectInventory inventory, FileAnalysis analysis, PatternOccurrence sink,
                                 boolean hasSources, boolean hasEntryPoint) {
        Finding finding = new Finding();
        finding.setStatus(FindingStatus.OPEN);
        finding.setRuleId(ruleIdFor(sink.getType()));
        finding.setTitle(titleFor(sink.getType()));
        finding.setVulnerabilityType(vulnerabilityTypeFor(sink.getType()));
        finding.setSeverity(severityFor(sink.getType()));
        finding.setConfidence(confidenceFor(hasSources, hasEntryPoint, sink.getType()));
        finding.setSource(sourceDescription(analysis));
        finding.setSink(sink.getSnippet());
        finding.setSummary(summaryFor(analysis, sink));
        finding.setPreconditions(preconditionsFor(analysis, sink));
        finding.setReproductionOutline(reproductionFor(analysis, sink));
        finding.setAffectedVersions(inventory.getProjectVersion());
        finding.setFixRecommendation(fixFor(sink.getType()));

        List<Location> locations = new ArrayList<Location>();
        locations.add(new Location(analysis.getFilePath().toString(), sink.getLine(), sink.getSnippet()));
        if (!analysis.getSources().isEmpty()) {
            PatternOccurrence source = analysis.getSources().get(0);
            locations.add(new Location(analysis.getFilePath().toString(), source.getLine(), source.getSnippet()));
        }
        finding.setLocations(locations);
        finding.setFingerprint(fingerprint(finding.getRuleId() + "|" + analysis.getFilePath() + "|" + sink.getLine()));
        return finding;
    }

    private ConfidenceLevel confidenceFor(boolean hasSources, boolean hasEntryPoint, String sinkType) {
        if (hasSources && hasEntryPoint) {
            return ConfidenceLevel.CONFIRMED;
        }
        if (hasSources || hasEntryPoint || "DESERIALIZATION".equals(sinkType)) {
            return ConfidenceLevel.HIGH_CONFIDENCE;
        }
        return ConfidenceLevel.NEEDS_REVIEW;
    }

    private String sourceDescription(FileAnalysis analysis) {
        if (analysis.getSources().isEmpty()) {
            return "No request source was resolved in the same file; review nearby call paths manually.";
        }
        PatternOccurrence source = analysis.getSources().get(0);
        return source.getType() + " at line " + source.getLine() + ": " + source.getSnippet();
    }

    private String preconditionsFor(FileAnalysis analysis, PatternOccurrence sink) {
        if (!analysis.getSources().isEmpty()) {
            return "User-controlled data appears to enter this file before reaching the sink " + sink.getType() + ".";
        }
        if (analysis.isSpringEntryPoint() || analysis.isServletEntryPoint()) {
            return "The sink is inside a web entry point; confirm whether attacker input can reach it.";
        }
        return "The sink is present, but a reachable attacker-controlled path still needs review.";
    }

    private String reproductionFor(FileAnalysis analysis, PatternOccurrence sink) {
        if (!analysis.getSources().isEmpty()) {
            return "Trace the request handler in " + analysis.getFilePath().getFileName()
                    + ", send crafted input to the identified HTTP source, and observe whether execution reaches "
                    + sink.getType() + " at line " + sink.getLine() + ".";
        }
        return "Review nearby callers to determine whether external input can reach line " + sink.getLine() + ".";
    }

    private String summaryFor(FileAnalysis analysis, PatternOccurrence sink) {
        StringBuilder builder = new StringBuilder();
        builder.append("Detected ").append(titleFor(sink.getType())).append(" in ")
                .append(analysis.getFilePath().getFileName());
        if (analysis.isSpringEntryPoint() || analysis.isServletEntryPoint()) {
            builder.append(" within a web entry point");
        }
        if (!analysis.getSources().isEmpty()) {
            builder.append(" with nearby request-derived input");
        }
        builder.append(".");
        return builder.toString();
    }

    private Severity severityFor(String sinkType) {
        if ("EXEC".equals(sinkType) || "SCRIPT".equals(sinkType) || "DESERIALIZATION".equals(sinkType)) {
            return Severity.HIGH;
        }
        return Severity.MEDIUM;
    }

    private String ruleIdFor(String sinkType) {
        if ("EXEC".equals(sinkType)) {
            return "JAVA-RCE-EXEC-001";
        }
        if ("DESERIALIZATION".equals(sinkType)) {
            return "JAVA-DESER-001";
        }
        if ("EXPRESSION".equals(sinkType)) {
            return "JAVA-EXPR-001";
        }
        if ("SCRIPT".equals(sinkType)) {
            return "JAVA-SCRIPT-001";
        }
        return "JAVA-REFLECT-001";
    }

    private String titleFor(String sinkType) {
        if ("EXEC".equals(sinkType)) {
            return "Potential command execution path";
        }
        if ("DESERIALIZATION".equals(sinkType)) {
            return "Potential unsafe deserialization";
        }
        if ("EXPRESSION".equals(sinkType)) {
            return "Potential expression or template execution";
        }
        if ("SCRIPT".equals(sinkType)) {
            return "Potential script execution";
        }
        return "Potential reflection or class loading abuse";
    }

    private String vulnerabilityTypeFor(String sinkType) {
        if ("EXEC".equals(sinkType)) {
            return "Command Injection / RCE";
        }
        if ("DESERIALIZATION".equals(sinkType)) {
            return "Unsafe Deserialization";
        }
        if ("EXPRESSION".equals(sinkType)) {
            return "Expression Injection";
        }
        if ("SCRIPT".equals(sinkType)) {
            return "Script Execution";
        }
        return "Reflection Abuse";
    }

    private String fixFor(String sinkType) {
        if ("EXEC".equals(sinkType)) {
            return "Avoid building commands from untrusted input, prefer fixed argument arrays, and enforce allow-lists.";
        }
        if ("DESERIALIZATION".equals(sinkType)) {
            return "Remove native deserialization for untrusted data, use safe formats, and add class allow-lists.";
        }
        if ("EXPRESSION".equals(sinkType)) {
            return "Do not evaluate user-controlled expressions; restrict expression features or replace with safe lookups.";
        }
        if ("SCRIPT".equals(sinkType)) {
            return "Disable dynamic script evaluation for untrusted data and restrict the script engine surface.";
        }
        return "Reduce reflective access on attacker-controlled values and add explicit type allow-lists.";
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
}
