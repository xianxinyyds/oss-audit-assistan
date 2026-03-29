package com.vibecoding.ossaudit.cli;

import com.vibecoding.ossaudit.core.model.ScanResult;
import com.vibecoding.ossaudit.github.GitHubDraftService;
import com.vibecoding.ossaudit.policy.ConfirmationPolicy;
import com.vibecoding.ossaudit.report.JsonStore;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Command(name = "draft-issue", mixinStandardHelpOptions = true, description = "Generate a local GitHub issue draft.")
public class GithubDraftIssueCommand implements Callable<Integer> {

    @Option(names = "--result", required = true, description = "Path to scan-result.json")
    private String resultPath;

    @Option(names = "--output", description = "Destination Markdown path, defaults next to the result")
    private String outputPath;

    @Option(names = "--confirm-external-share", description = "Required before generating GitHub issue material")
    private boolean confirmExternalShare;

    public Integer call() throws Exception {
        ConfirmationPolicy.requireExternalShareConfirmation(confirmExternalShare);

        JsonStore jsonStore = new JsonStore();
        Path input = Paths.get(resultPath).toAbsolutePath().normalize();
        ScanResult scanResult = jsonStore.read(input);
        Path output = outputPath == null
                ? input.getParent().resolve("github-issue-draft.md")
                : Paths.get(outputPath).toAbsolutePath().normalize();

        GitHubDraftService service = new GitHubDraftService();
        service.writeDraft(output, scanResult);

        System.out.println("GitHub issue draft written to " + output);
        return 0;
    }
}
