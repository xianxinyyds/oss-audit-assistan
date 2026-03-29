package com.vibecoding.ossaudit.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class IgnoreConfigLoader {

    public IgnoreConfig load(Path repositoryPath) throws IOException {
        IgnoreConfig config = new IgnoreConfig();
        Path ignoreFile = repositoryPath.resolve(".ossguard-ignore");
        if (!Files.exists(ignoreFile)) {
            return config;
        }

        List<String> lines = Files.readAllLines(ignoreFile, StandardCharsets.UTF_8);
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            if (trimmed.startsWith("rule:")) {
                config.getIgnoredRules().add(trimmed.substring("rule:".length()).trim());
            } else if (trimmed.startsWith("fingerprint:")) {
                config.getIgnoredFingerprints().add(trimmed.substring("fingerprint:".length()).trim());
            }
        }
        return config;
    }
}
