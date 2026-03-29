package com.vibecoding.ossaudit.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.vibecoding.ossaudit.core.model.ScanResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class JsonStore {
    private final ObjectMapper objectMapper;

    public JsonStore() {
        objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    public void write(Path output, ScanResult scanResult) throws IOException {
        Files.createDirectories(output.getParent());
        objectMapper.writeValue(output.toFile(), scanResult);
    }

    public ScanResult read(Path input) throws IOException {
        return objectMapper.readValue(input.toFile(), ScanResult.class);
    }
}
