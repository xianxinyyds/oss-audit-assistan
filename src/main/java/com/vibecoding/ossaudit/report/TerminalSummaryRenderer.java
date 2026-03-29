package com.vibecoding.ossaudit.report;

import com.vibecoding.ossaudit.core.model.ConfidenceLevel;
import com.vibecoding.ossaudit.core.model.Finding;
import com.vibecoding.ossaudit.core.model.ScanResult;
import picocli.CommandLine;

public class TerminalSummaryRenderer {

    public void render(ScanResult scanResult, boolean includeSensitive) {
        int confirmed = 0;
        int highConfidence = 0;
        int needsReview = 0;
        for (Finding finding : scanResult.getFindings()) {
            if (finding.getConfidence() == ConfidenceLevel.CONFIRMED) {
                confirmed++;
            } else if (finding.getConfidence() == ConfidenceLevel.HIGH_CONFIDENCE) {
                highConfidence++;
            } else {
                needsReview++;
            }
        }

        System.out.println(CommandLine.Help.Ansi.AUTO.string("@|bold,green Scan complete|@"));
        System.out.println("Project: " + scanResult.getProjectName() + " (" + scanResult.getProjectVersion() + ")");
        System.out.println("Confirmed: " + confirmed + ", High-confidence: " + highConfidence + ", Needs-review: " + needsReview);

        int previewLimit = Math.min(scanResult.getFindings().size(), 5);
        for (int index = 0; index < previewLimit; index++) {
            Finding finding = scanResult.getFindings().get(index);
            System.out.println(" - [" + finding.getConfidence() + "] " + finding.getRuleId() + " :: " + finding.getTitle());
        }
        if (!includeSensitive && !scanResult.getFindings().isEmpty()) {
            System.out.println("Sensitive reproduction details were redacted from the Markdown output.");
        }
    }
}
