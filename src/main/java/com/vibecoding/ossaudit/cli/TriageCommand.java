package com.vibecoding.ossaudit.cli;

import com.vibecoding.ossaudit.core.model.FindingStatus;
import com.vibecoding.ossaudit.report.JsonStore;
import com.vibecoding.ossaudit.triage.TriageService;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Command(name = "triage", mixinStandardHelpOptions = true, description = "Update finding status or persist ignore entries.")
public class TriageCommand implements Callable<Integer> {

    @Option(names = "--result", required = true, description = "Path to scan-result.json")
    private String resultPath;

    @Option(names = "--fingerprint", required = true, description = "Finding fingerprint")
    private String fingerprint;

    @Option(names = "--status", required = true, description = "New status: ${COMPLETION-CANDIDATES}")
    private FindingStatus status;

    @Option(names = "--persist-ignore", description = "Persist the finding fingerprint to <repo>/.ossguard-ignore")
    private boolean persistIgnore;

    public Integer call() throws Exception {
        Path input = Paths.get(resultPath).toAbsolutePath().normalize();
        JsonStore store = new JsonStore();
        TriageService service = new TriageService(store);
        service.updateFindingStatus(input, fingerprint, status, persistIgnore);
        System.out.println("Updated finding " + fingerprint + " to " + status);
        return 0;
    }
}
