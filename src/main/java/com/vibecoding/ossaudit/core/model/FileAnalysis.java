package com.vibecoding.ossaudit.core.model;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class FileAnalysis {
    private Path filePath;
    private boolean springEntryPoint;
    private boolean servletEntryPoint;
    private List<PatternOccurrence> sources = new ArrayList<PatternOccurrence>();
    private List<PatternOccurrence> sinks = new ArrayList<PatternOccurrence>();

    public FileAnalysis(Path filePath) {
        this.filePath = filePath;
    }

    public Path getFilePath() {
        return filePath;
    }

    public boolean isSpringEntryPoint() {
        return springEntryPoint;
    }

    public void setSpringEntryPoint(boolean springEntryPoint) {
        this.springEntryPoint = springEntryPoint;
    }

    public boolean isServletEntryPoint() {
        return servletEntryPoint;
    }

    public void setServletEntryPoint(boolean servletEntryPoint) {
        this.servletEntryPoint = servletEntryPoint;
    }

    public List<PatternOccurrence> getSources() {
        return sources;
    }

    public List<PatternOccurrence> getSinks() {
        return sinks;
    }
}
