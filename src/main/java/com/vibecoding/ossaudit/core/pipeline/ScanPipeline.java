package com.vibecoding.ossaudit.core.pipeline;

import com.vibecoding.ossaudit.config.IgnoreConfig;
import com.vibecoding.ossaudit.config.IgnoreConfigLoader;
import com.vibecoding.ossaudit.core.model.FileAnalysis;
import com.vibecoding.ossaudit.core.model.Finding;
import com.vibecoding.ossaudit.core.model.FindingStatus;
import com.vibecoding.ossaudit.core.model.ProjectInventory;
import com.vibecoding.ossaudit.core.model.ScanResult;
import com.vibecoding.ossaudit.dependency.DependencyEngine;
import com.vibecoding.ossaudit.repo.RepoIntakeService;
import com.vibecoding.ossaudit.rule.RuleEngine;
import com.vibecoding.ossaudit.semantic.JavaProjectAnalyzer;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

public class ScanPipeline {
    private final RepoIntakeService repoIntakeService = new RepoIntakeService();
    private final JavaProjectAnalyzer javaProjectAnalyzer = new JavaProjectAnalyzer();
    private final RuleEngine ruleEngine = new RuleEngine();
    private final DependencyEngine dependencyEngine = new DependencyEngine();
    private final IgnoreConfigLoader ignoreConfigLoader = new IgnoreConfigLoader();

    public ScanResult scan(Path repository, Set<String> enabledRules, Set<String> disabledRules) throws Exception {
        ProjectInventory inventory = repoIntakeService.inspect(repository);
        List<FileAnalysis> analyses = javaProjectAnalyzer.analyze(inventory);
        List<Finding> findings = new ArrayList<Finding>();
        findings.addAll(ruleEngine.detect(inventory, analyses));
        findings.addAll(dependencyEngine.detect(inventory, analyses));

        IgnoreConfig ignoreConfig = ignoreConfigLoader.load(repository);
        List<Finding> filteredFindings = new ArrayList<Finding>();
        for (Finding finding : findings) {
            if (!enabledRules.isEmpty() && !enabledRules.contains(finding.getRuleId())) {
                continue;
            }
            if (disabledRules.contains(finding.getRuleId())) {
                continue;
            }
            if (ignoreConfig.getIgnoredRules().contains(finding.getRuleId())
                    || ignoreConfig.getIgnoredFingerprints().contains(finding.getFingerprint())) {
                finding.setStatus(FindingStatus.IGNORED);
            }
            filteredFindings.add(finding);
        }

        Collections.sort(filteredFindings, new Comparator<Finding>() {
            public int compare(Finding left, Finding right) {
                return left.getConfidence().compareTo(right.getConfidence());
            }
        });

        ScanResult result = new ScanResult();
        result.setToolVersion("0.1.0");
        result.setRepositoryPath(repository.toString());
        result.setProjectName(inventory.getProjectName());
        result.setProjectVersion(inventory.getProjectVersion());
        result.setScannedAt(Instant.now().toString());
        result.setFindings(filteredFindings);
        return result;
    }
}
