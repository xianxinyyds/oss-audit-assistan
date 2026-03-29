package com.vibecoding.ossaudit.repo;

import com.vibecoding.ossaudit.core.model.DependencyRecord;
import com.vibecoding.ossaudit.core.model.ProjectInventory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class RepoIntakeService {
    private static final Pattern GRADLE_COORDINATE =
            Pattern.compile("(implementation|api|compile|runtimeOnly|testImplementation)\\s+['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]");
    private static final Pattern GRADLE_VERSION = Pattern.compile("(?m)^\\s*version\\s*=\\s*['\"]([^'\"]+)['\"]");

    public ProjectInventory inspect(Path repository) throws IOException {
        if (!Files.isDirectory(repository)) {
            throw new IllegalArgumentException("Repository path does not exist: " + repository);
        }

        ProjectInventory inventory = new ProjectInventory();
        inventory.setRepositoryPath(repository);
        inventory.setProjectName(repository.getFileName().toString());

        try (Stream<Path> stream = Files.walk(repository)) {
            stream.filter(Files::isRegularFile).forEach(path -> classify(path, inventory));
        }

        if (inventory.getProjectVersion() == null) {
            inventory.setProjectVersion("unresolved-from-build-files");
        }
        return inventory;
    }

    private void classify(Path path, ProjectInventory inventory) {
        String name = path.getFileName().toString();
        try {
            if (name.endsWith(".java")) {
                inventory.getJavaFiles().add(path);
            } else if ("pom.xml".equalsIgnoreCase(name)) {
                inventory.getPomFiles().add(path);
                parsePom(path, inventory);
            } else if ("build.gradle".equalsIgnoreCase(name) || "build.gradle.kts".equalsIgnoreCase(name)) {
                inventory.getGradleFiles().add(path);
                parseGradle(path, inventory);
            }
        } catch (Exception ignored) {
            // Keep the first version resilient when individual files are malformed.
        }
    }

    private void parsePom(Path pom, ProjectInventory inventory) throws Exception {
        Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(pom.toFile());
        document.getDocumentElement().normalize();

        if (inventory.getProjectVersion() == null) {
            NodeList versionNodes = document.getDocumentElement().getElementsByTagName("version");
            if (versionNodes.getLength() > 0) {
                inventory.setProjectVersion(versionNodes.item(0).getTextContent().trim());
            }
        }

        NodeList dependencyNodes = document.getElementsByTagName("dependency");
        for (int i = 0; i < dependencyNodes.getLength(); i++) {
            Node dependencyNode = dependencyNodes.item(i);
            if (dependencyNode.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            Element element = (Element) dependencyNode;
            String groupId = text(element, "groupId");
            String artifactId = text(element, "artifactId");
            String version = text(element, "version");
            if (groupId != null && artifactId != null && version != null) {
                inventory.getDependencies().add(new DependencyRecord(groupId, artifactId, version, pom.toString()));
            }
        }
    }

    private void parseGradle(Path gradle, ProjectInventory inventory) throws IOException {
        List<String> lines = Files.readAllLines(gradle, StandardCharsets.UTF_8);
        StringBuilder contentBuilder = new StringBuilder();
        for (String line : lines) {
            contentBuilder.append(line).append('\n');
        }
        String content = contentBuilder.toString();

        if (inventory.getProjectVersion() == null) {
            Matcher versionMatcher = GRADLE_VERSION.matcher(content);
            if (versionMatcher.find()) {
                inventory.setProjectVersion(versionMatcher.group(1));
            }
        }

        for (String line : lines) {
            Matcher matcher = GRADLE_COORDINATE.matcher(line.trim());
            if (matcher.find()) {
                inventory.getDependencies().add(new DependencyRecord(
                        matcher.group(2),
                        matcher.group(3),
                        matcher.group(4),
                        gradle.toString()
                ));
            }
        }
    }

    private String text(Element element, String tagName) {
        NodeList nodes = element.getElementsByTagName(tagName);
        if (nodes.getLength() == 0) {
            return null;
        }
        return nodes.item(0).getTextContent().trim();
    }
}
