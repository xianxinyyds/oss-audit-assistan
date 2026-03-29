package com.vibecoding.ossaudit.core.model;

import java.util.ArrayList;
import java.util.List;

public class ScanResult {
    private String toolVersion;
    private String repositoryPath;
    private String projectName;
    private String projectVersion;
    private String scannedAt;
    private List<Finding> findings = new ArrayList<Finding>();

    public String getToolVersion() {
        return toolVersion;
    }

    public void setToolVersion(String toolVersion) {
        this.toolVersion = toolVersion;
    }

    public String getRepositoryPath() {
        return repositoryPath;
    }

    public void setRepositoryPath(String repositoryPath) {
        this.repositoryPath = repositoryPath;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getProjectVersion() {
        return projectVersion;
    }

    public void setProjectVersion(String projectVersion) {
        this.projectVersion = projectVersion;
    }

    public String getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(String scannedAt) {
        this.scannedAt = scannedAt;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public void setFindings(List<Finding> findings) {
        this.findings = findings;
    }

    public boolean hasBlockingFindings() {
        for (Finding finding : findings) {
            if (finding.getConfidence() == ConfidenceLevel.CONFIRMED
                    || finding.getConfidence() == ConfidenceLevel.HIGH_CONFIDENCE) {
                return true;
            }
        }
        return false;
    }
}
