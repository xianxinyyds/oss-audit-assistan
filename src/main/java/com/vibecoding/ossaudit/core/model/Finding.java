package com.vibecoding.ossaudit.core.model;

import java.util.ArrayList;
import java.util.List;

public class Finding {
    private String fingerprint;
    private String ruleId;
    private String title;
    private String summary;
    private String vulnerabilityType;
    private Severity severity;
    private ConfidenceLevel confidence;
    private FindingStatus status;
    private String source;
    private String sink;
    private String preconditions;
    private String reproductionOutline;
    private String affectedVersions;
    private String fixRecommendation;
    private String dependencyContext;
    private List<Location> locations = new ArrayList<Location>();

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getVulnerabilityType() {
        return vulnerabilityType;
    }

    public void setVulnerabilityType(String vulnerabilityType) {
        this.vulnerabilityType = vulnerabilityType;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public ConfidenceLevel getConfidence() {
        return confidence;
    }

    public void setConfidence(ConfidenceLevel confidence) {
        this.confidence = confidence;
    }

    public FindingStatus getStatus() {
        return status;
    }

    public void setStatus(FindingStatus status) {
        this.status = status;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getSink() {
        return sink;
    }

    public void setSink(String sink) {
        this.sink = sink;
    }

    public String getPreconditions() {
        return preconditions;
    }

    public void setPreconditions(String preconditions) {
        this.preconditions = preconditions;
    }

    public String getReproductionOutline() {
        return reproductionOutline;
    }

    public void setReproductionOutline(String reproductionOutline) {
        this.reproductionOutline = reproductionOutline;
    }

    public String getAffectedVersions() {
        return affectedVersions;
    }

    public void setAffectedVersions(String affectedVersions) {
        this.affectedVersions = affectedVersions;
    }

    public String getFixRecommendation() {
        return fixRecommendation;
    }

    public void setFixRecommendation(String fixRecommendation) {
        this.fixRecommendation = fixRecommendation;
    }

    public String getDependencyContext() {
        return dependencyContext;
    }

    public void setDependencyContext(String dependencyContext) {
        this.dependencyContext = dependencyContext;
    }

    public List<Location> getLocations() {
        return locations;
    }

    public void setLocations(List<Location> locations) {
        this.locations = locations;
    }
}
