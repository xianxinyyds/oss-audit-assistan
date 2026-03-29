package com.vibecoding.ossaudit.cli;

import com.vibecoding.ossaudit.core.model.ScanResult;
import com.vibecoding.ossaudit.core.pipeline.ScanPipeline;
import com.vibecoding.ossaudit.policy.ConfirmationPolicy;
import com.vibecoding.ossaudit.report.JsonStore;
import com.vibecoding.ossaudit.report.MarkdownReportWriter;
import com.vibecoding.ossaudit.report.TerminalSummaryRenderer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.Callable;

@Command(name = "scan", mixinStandardHelpOptions = true, description = "Scan an authorized repository.")
public class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Repository path to scan")
    private String repoPath;

    @Option(names = "--output-dir", description = "Output directory, defaults to <repo>/.ossguard")
    private String outputDir;

    @Option(names = "--include-sensitive", description = "Include sensitive reproduction details in the Markdown report")
    private boolean includeSensitive;

    @Option(names = "--confirm-sensitive-export", description = "Required when exporting sensitive details")
    private boolean confirmSensitiveExport;

    @Option(names = "--enable-rule", split = ",", description = "Comma-separated allow list of rule IDs")
    private Set<String> enabledRules = new LinkedHashSet<String>();

    @Option(names = "--disable-rule", split = ",", description = "Comma-separated deny list of rule IDs")
    private Set<String> disabledRules = new LinkedHashSet<String>();

    public Integer call() throws Exception {
        ConfirmationPolicy.requireSensitiveExportConfirmation(includeSensitive, confirmSensitiveExport);

        Path repository = Paths.get(repoPath).toAbsolutePath().normalize();
        Path resolvedOutputDir = outputDir == null
                ? repository.resolve(".ossguard")
                : Paths.get(outputDir).toAbsolutePath().normalize();

        ScanPipeline pipeline = new ScanPipeline();
        ScanResult scanResult = pipeline.scan(repository, enabledRules, disabledRules);

        JsonStore jsonStore = new JsonStore();
        Path resultPath = resolvedOutputDir.resolve("scan-result.json");
        jsonStore.write(resultPath, scanResult);

        MarkdownReportWriter markdownReportWriter = new MarkdownReportWriter();
        Path markdownPath = resolvedOutputDir.resolve("report.md");
        markdownReportWriter.write(markdownPath, scanResult, includeSensitive);

        TerminalSummaryRenderer summaryRenderer = new TerminalSummaryRenderer();
        summaryRenderer.render(scanResult, includeSensitive);
        System.out.println("JSON result: " + resultPath);
        System.out.println("Markdown report: " + markdownPath);

        return scanResult.hasBlockingFindings() ? 2 : 0;
    }
}
