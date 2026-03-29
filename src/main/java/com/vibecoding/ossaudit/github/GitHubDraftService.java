package com.vibecoding.ossaudit.github;

import com.vibecoding.ossaudit.core.model.Finding;
import com.vibecoding.ossaudit.core.model.FindingStatus;
import com.vibecoding.ossaudit.core.model.ScanResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class GitHubDraftService {

    public void writeDraft(Path output, ScanResult scanResult) throws IOException {
        Files.createDirectories(output.getParent());
        Files.write(output, render(scanResult).getBytes(StandardCharsets.UTF_8));
    }

    public String render(ScanResult scanResult) {
        StringBuilder builder = new StringBuilder();
        builder.append("# Security Review Draft\n\n");
        builder.append("Repository: ").append(scanResult.getRepositoryPath()).append("\n\n");
        for (Finding finding : scanResult.getFindings()) {
            if (finding.getStatus() == FindingStatus.IGNORED
                    || finding.getStatus() == FindingStatus.FALSE_POSITIVE) {
                continue;
            }
            builder.append("## ").append(finding.getTitle()).append("\n\n");
            builder.append("- Rule ID: ").append(finding.getRuleId()).append('\n');
            builder.append("- Confidence: ").append(finding.getConfidence()).append('\n');
            builder.append("- Severity: ").append(finding.getSeverity()).append('\n');
            builder.append("- Vulnerability Type: ").append(finding.getVulnerabilityType()).append('\n');
            builder.append("- Preconditions: ").append(finding.getPreconditions()).append('\n');
            builder.append("- Summary: ").append(finding.getSummary()).append('\n');
            builder.append("- Recommended Fix: ").append(finding.getFixRecommendation()).append("\n\n");
        }
        return builder.toString();
    }
}
