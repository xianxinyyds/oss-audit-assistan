package com.vibecoding.ossaudit.core.model;

public class Location {
    private String filePath;
    private int line;
    private String snippet;

    public Location() {
    }

    public Location(String filePath, int line, String snippet) {
        this.filePath = filePath;
        this.line = line;
        this.snippet = snippet;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public int getLine() {
        return line;
    }

    public void setLine(int line) {
        this.line = line;
    }

    public String getSnippet() {
        return snippet;
    }

    public void setSnippet(String snippet) {
        this.snippet = snippet;
    }
}
