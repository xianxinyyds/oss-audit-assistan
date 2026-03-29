package com.vibecoding.ossaudit.triage;

import com.vibecoding.ossaudit.core.model.Finding;
import com.vibecoding.ossaudit.core.model.FindingStatus;
import com.vibecoding.ossaudit.core.model.ScanResult;
import com.vibecoding.ossaudit.report.JsonStore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class TriageService {
    private final JsonStore jsonStore;

    public TriageService(JsonStore jsonStore) {
        this.jsonStore = jsonStore;
    }

    public void updateFindingStatus(Path resultPath, String fingerprint, FindingStatus status,
                                    boolean persistIgnore) throws IOException {
        ScanResult scanResult = jsonStore.read(resultPath);
        boolean updated = false;
        for (Finding finding : scanResult.getFindings()) {
            if (fingerprint.equals(finding.getFingerprint())) {
                finding.setStatus(status);
                updated = true;
                break;
            }
        }
        if (!updated) {
            throw new IllegalArgumentException("Finding fingerprint not found: " + fingerprint);
        }
        jsonStore.write(resultPath, scanResult);

        if (persistIgnore && (status == FindingStatus.FALSE_POSITIVE || status == FindingStatus.IGNORED)) {
            appendIgnoreEntry(Paths.get(scanResult.getRepositoryPath()).resolve(".ossguard-ignore"), fingerprint);
        }
    }

    private void appendIgnoreEntry(Path ignoreFile, String fingerprint) throws IOException {
        Files.createDirectories(ignoreFile.getParent());
        String line = "fingerprint:" + fingerprint + System.lineSeparator();
        if (Files.exists(ignoreFile)) {
            Files.write(ignoreFile, line.getBytes(StandardCharsets.UTF_8), StandardOpenOption.APPEND);
        } else {
            Files.write(ignoreFile, line.getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
        }
    }
}
