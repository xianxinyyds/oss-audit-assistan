package com.vibecoding.ossaudit.cli;

import com.vibecoding.ossaudit.core.model.ScanResult;
import com.vibecoding.ossaudit.policy.ConfirmationPolicy;
import com.vibecoding.ossaudit.report.JsonStore;
import com.vibecoding.ossaudit.report.MarkdownReportWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Command(name = "report", mixinStandardHelpOptions = true, description = "Render a Markdown report from a prior scan result.")
public class ReportCommand implements Callable<Integer> {

    @Option(names = "--result", required = true, description = "Path to scan-result.json")
    private String resultPath;

    @Option(names = "--output", description = "Destination Markdown path, defaults next to the result")
    private String outputPath;

    @Option(names = "--include-sensitive", description = "Include sensitive reproduction details")
    private boolean includeSensitive;

    @Option(names = "--confirm-sensitive-export", description = "Required when exporting sensitive details")
    private boolean confirmSensitiveExport;

    public Integer call() throws Exception {
        ConfirmationPolicy.requireSensitiveExportConfirmation(includeSensitive, confirmSensitiveExport);

        JsonStore jsonStore = new JsonStore();
        Path input = Paths.get(resultPath).toAbsolutePath().normalize();
        ScanResult scanResult = jsonStore.read(input);

        Path output = outputPath == null
                ? input.getParent().resolve("report.md")
                : Paths.get(outputPath).toAbsolutePath().normalize();

        MarkdownReportWriter writer = new MarkdownReportWriter();
        writer.write(output, scanResult, includeSensitive);

        System.out.println("Markdown report written to " + output);
        return 0;
    }
}
