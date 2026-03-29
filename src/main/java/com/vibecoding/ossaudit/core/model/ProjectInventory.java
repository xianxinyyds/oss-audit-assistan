package com.vibecoding.ossaudit.core.model;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ProjectInventory {
    private Path repositoryPath;
    private String projectName;
    private String projectVersion;
    private List<Path> javaFiles = new ArrayList<Path>();
    private List<Path> pomFiles = new ArrayList<Path>();
    private List<Path> gradleFiles = new ArrayList<Path>();
    private List<DependencyRecord> dependencies = new ArrayList<DependencyRecord>();

    public Path getRepositoryPath() {
        return repositoryPath;
    }

    public void setRepositoryPath(Path repositoryPath) {
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

    public List<Path> getJavaFiles() {
        return javaFiles;
    }

    public List<Path> getPomFiles() {
        return pomFiles;
    }

    public List<Path> getGradleFiles() {
        return gradleFiles;
    }

    public List<DependencyRecord> getDependencies() {
        return dependencies;
    }
}
