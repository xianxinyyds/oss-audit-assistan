package com.vibecoding.ossaudit.core.model;

public class DependencyRecord {
    private String groupId;
    private String artifactId;
    private String version;
    private String sourceFile;

    public DependencyRecord() {
    }

    public DependencyRecord(String groupId, String artifactId, String version, String sourceFile) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
        this.sourceFile = sourceFile;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getArtifactId() {
        return artifactId;
    }

    public String getVersion() {
        return version;
    }

    public String getSourceFile() {
        return sourceFile;
    }
}
