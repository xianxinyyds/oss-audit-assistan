# OSS Audit Assistant

`oss-audit-assistant` is a Java-first CLI for auditing authorized open source repositories. The first cut focuses on Java projects, prioritizes Spring-based applications, and produces triaged findings plus Markdown reports close to disclosure workflows.

## Included in this version

- Java repository intake for source files, `pom.xml`, and `build.gradle`
- Heuristic analysis for common Spring and Servlet entry points
- Rule-based detection for:
  - command execution
  - dangerous deserialization
  - expression and template execution
  - script execution
  - reflection and class loading chains
- Built-in dependency checks against a small advisory catalog
- Confidence levels: `confirmed`, `high-confidence`, `needs-review`
- Markdown and JSON report generation
- Triage support for false positives and ignore persistence
- GitHub issue draft generation with confirmation gates

## Quick start

```bash
mvn -q compile
mvn -q exec:java -Dexec.args="scan C:\path\to\authorized-repo"
```

## Commands

```bash
mvn -q exec:java -Dexec.args="scan <repo>"
mvn -q exec:java -Dexec.args="report --result <repo>/.ossguard/scan-result.json"
mvn -q exec:java -Dexec.args="triage --result <repo>/.ossguard/scan-result.json --fingerprint <fp> --status FALSE_POSITIVE --persist-ignore"
mvn -q exec:java -Dexec.args="github draft-issue --result <repo>/.ossguard/scan-result.json --confirm-external-share"
```

## Safety defaults

- Sensitive reproduction details are hidden by default.
- Exporting sensitive details requires `--include-sensitive` and `--confirm-sensitive-export`.
- Generating GitHub issue drafts requires `--confirm-external-share`.

## Notes

- This version prefers explainable results over broad coverage.
- Dependency intelligence uses a small embedded catalog and is designed to be replaced by a richer advisory source later.
- Findings are intended for authorized review workflows only.
