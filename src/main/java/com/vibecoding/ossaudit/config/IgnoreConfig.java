package com.vibecoding.ossaudit.config;

import java.util.LinkedHashSet;
import java.util.Set;

public class IgnoreConfig {
    private final Set<String> ignoredRules = new LinkedHashSet<String>();
    private final Set<String> ignoredFingerprints = new LinkedHashSet<String>();

    public Set<String> getIgnoredRules() {
        return ignoredRules;
    }

    public Set<String> getIgnoredFingerprints() {
        return ignoredFingerprints;
    }
}
