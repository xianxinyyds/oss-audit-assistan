package com.vibecoding.ossaudit.semantic;

import com.vibecoding.ossaudit.core.model.FileAnalysis;
import com.vibecoding.ossaudit.core.model.PatternOccurrence;
import com.vibecoding.ossaudit.core.model.ProjectInventory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class JavaProjectAnalyzer {
    private static final Map<String, Pattern> SOURCE_PATTERNS = new LinkedHashMap<String, Pattern>();
    private static final Map<String, Pattern> SINK_PATTERNS = new LinkedHashMap<String, Pattern>();

    static {
        SOURCE_PATTERNS.put("REQUEST_PARAM", Pattern.compile("@RequestParam|getParameter\\("));
        SOURCE_PATTERNS.put("HEADER_OR_COOKIE", Pattern.compile("@RequestHeader|@CookieValue|getHeader\\(|getCookies\\("));
        SOURCE_PATTERNS.put("REQUEST_BODY", Pattern.compile("@RequestBody|readValue\\(|parseObject\\("));

        SINK_PATTERNS.put("EXEC", Pattern.compile("Runtime\\.getRuntime\\(\\)\\.exec\\(|new\\s+ProcessBuilder\\("));
        SINK_PATTERNS.put("DESERIALIZATION", Pattern.compile("new\\s+ObjectInputStream\\(|readObject\\(|XMLDecoder\\("));
        SINK_PATTERNS.put("EXPRESSION", Pattern.compile("SpelExpressionParser|parseExpression\\(|Ognl\\.getValue\\("));
        SINK_PATTERNS.put("SCRIPT", Pattern.compile("ScriptEngineManager|\\.eval\\("));
        SINK_PATTERNS.put("REFLECTION", Pattern.compile("Class\\.forName\\(|getDeclaredMethod\\(|newInstance\\("));
    }

    public List<FileAnalysis> analyze(ProjectInventory inventory) throws IOException {
        List<FileAnalysis> analyses = new ArrayList<FileAnalysis>();
        for (Path javaFile : inventory.getJavaFiles()) {
            analyses.add(analyzeFile(javaFile));
        }
        return analyses;
    }

    private FileAnalysis analyzeFile(Path path) throws IOException {
        FileAnalysis analysis = new FileAnalysis(path);
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        for (int index = 0; index < lines.size(); index++) {
            String line = lines.get(index);
            String trimmed = line.trim();
            if (trimmed.contains("@RestController")
                    || trimmed.contains("@Controller")
                    || trimmed.contains("@RequestMapping")
                    || trimmed.contains("@GetMapping")
                    || trimmed.contains("@PostMapping")) {
                analysis.setSpringEntryPoint(true);
            }
            if (trimmed.contains("extends HttpServlet")
                    || trimmed.contains("doGet(")
                    || trimmed.contains("doPost(")) {
                analysis.setServletEntryPoint(true);
            }
            detectOccurrences(index + 1, line, SOURCE_PATTERNS, analysis.getSources(), path);
            detectOccurrences(index + 1, line, SINK_PATTERNS, analysis.getSinks(), path);
        }
        return analysis;
    }

    private void detectOccurrences(int lineNumber, String line, Map<String, Pattern> patterns,
                                   List<PatternOccurrence> target, Path path) {
        for (Map.Entry<String, Pattern> entry : patterns.entrySet()) {
            if (entry.getValue().matcher(line).find()) {
                target.add(new PatternOccurrence(entry.getKey(), lineNumber, line.trim(), path.getFileName().toString()));
            }
        }
    }
}
