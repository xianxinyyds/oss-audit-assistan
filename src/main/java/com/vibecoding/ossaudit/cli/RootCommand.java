package com.vibecoding.ossaudit.cli;

import picocli.CommandLine.Command;

@Command(
        name = "ossguard",
        mixinStandardHelpOptions = true,
        version = "0.1.0",
        description = "Audit authorized Java repositories for high-risk vulnerability patterns.",
        subcommands = {
                ScanCommand.class,
                ReportCommand.class,
                TriageCommand.class,
                GithubCommand.class
        }
)
public class RootCommand implements Runnable {

    public void run() {
        System.out.println("Use a subcommand such as scan, report, triage, or github draft-issue.");
    }
}
