package com.vibecoding.ossaudit.cli;

import picocli.CommandLine.Command;

@Command(
        name = "github",
        mixinStandardHelpOptions = true,
        description = "GitHub-oriented helper commands.",
        subcommands = {GithubDraftIssueCommand.class}
)
public class GithubCommand implements Runnable {

    public void run() {
        System.out.println("Use the draft-issue subcommand.");
    }
}
