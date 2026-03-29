package com.vibecoding.ossaudit.report;

import com.vibecoding.ossaudit.core.model.Finding;
import com.vibecoding.ossaudit.core.model.Location;
import com.vibecoding.ossaudit.core.model.ScanResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class MarkdownReportWriter {

    public void write(Path output, ScanResult scanResult, boolean includeSensitive) throws IOException {
        Files.createDirectories(output.getParent());
        Files.write(output, render(scanResult, includeSensitive).getBytes(StandardCharsets.UTF_8));
    }

    public String render(ScanResult scanResult, boolean includeSensitive) {
        StringBuilder builder = new StringBuilder();
        builder.append("# OSS Audit Report\n\n");
        builder.append("- Project: ").append(scanResult.getProjectName()).append('\n');
        builder.append("- Version: ").append(scanResult.getProjectVersion()).append('\n');
        builder.append("- Repository: ").append(scanResult.getRepositoryPath()).append('\n');
        builder.append("- Scanned At: ").append(scanResult.getScannedAt()).append("\n\n");
        builder.append("## Findings\n\n");

        if (scanResult.getFindings().isEmpty()) {
            builder.append("No findings were produced by the current ruleset.\n");
            return builder.toString();
        }

        for (Finding finding : scanResult.getFindings()) {
            builder.append("### ").append(finding.getTitle()).append("\n\n");
            builder.append("- Rule ID: ").append(finding.getRuleId()).append('\n');
            builder.append("- Severity: ").append(finding.getSeverity()).append('\n');
            builder.append("- Confidence: ").append(finding.getConfidence()).append('\n');
            builder.append("- Status: ").append(finding.getStatus()).append('\n');
            builder.append("- Vulnerability Type: ").append(finding.getVulnerabilityType()).append('\n');
            builder.append("- Trigger Preconditions: ").append(finding.getPreconditions()).append('\n');
            builder.append("- Affected Versions: ").append(finding.getAffectedVersions()).append('\n');
            builder.append("- Dependency Context: ").append(nvl(finding.getDependencyContext())).append('\n');
            builder.append("- Summary: ").append(finding.getSummary()).append('\n');
            builder.append("- Source Evidence: ").append(nvl(finding.getSource())).append('\n');
            builder.append("- Sink Evidence: ").append(nvl(finding.getSink())).append('\n');
            builder.append("- Fix Recommendation: ").append(nvl(finding.getFixRecommendation())).append('\n');
            builder.append("- Fingerprint: ").append(finding.getFingerprint()).append("\n\n");

            builder.append("#### Locations\n\n");
            for (Location location : finding.getLocations()) {
                builder.append("- `").append(location.getFilePath()).append(":").append(location.getLine())
                        .append("` -> `").append(location.getSnippet()).append("`\n");
            }
            builder.append('\n');

            builder.append("#### Reproduction Outline\n\n");
            if (includeSensitive) {
                builder.append(finding.getReproductionOutline()).append("\n\n");
            } else {
                builder.append("Sensitive reproduction details are hidden. Re-run with `--include-sensitive --confirm-sensitive-export` to expand this section.\n\n");
            }
        }
        return builder.toString();
    }

    private String nvl(String input) {
        return input == null ? "n/a" : input;
    }
}
