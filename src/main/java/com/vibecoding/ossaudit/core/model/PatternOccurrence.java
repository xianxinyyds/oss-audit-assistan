package com.vibecoding.ossaudit.core.model;

public class PatternOccurrence {
    private String type;
    private int line;
    private String snippet;
    private String detail;

    public PatternOccurrence(String type, int line, String snippet, String detail) {
        this.type = type;
        this.line = line;
        this.snippet = snippet;
        this.detail = detail;
    }

    public String getType() {
        return type;
    }

    public int getLine() {
        return line;
    }

    public String getSnippet() {
        return snippet;
    }

    public String getDetail() {
        return detail;
    }
}
