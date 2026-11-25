package com.phishguard;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * HistoryManager saves every scan in a CSV file and reads it back.
 *
 * CSV = "comma separated values". Each line is one scan:
 *   DateTime,ScanType,RiskScore,Classification,Summary
 *   "2026-11-24 10:15:02","EMAIL",87,"HIGH RISK","Email from ... - OTP request, ..."
 *
 * Text values are wrapped in double quotes so that commas inside a summary
 * do not break the file. No database is needed.
 */
public class HistoryManager {

    public static final String HEADER = "DateTime,ScanType,RiskScore,Classification,Summary";
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final Path file;

    /** One line of the history file. */
    public static class ScanRecord {
        public final String dateTime;
        public final String scanType;
        public final int riskScore;
        public final String classification;
        public final String summary;

        public ScanRecord(String dateTime, String scanType, int riskScore, String classification, String summary) {
            this.dateTime = dateTime;
            this.scanType = scanType;
            this.riskScore = riskScore;
            this.classification = classification;
            this.summary = summary;
        }
    }

    public HistoryManager(String fileName) {
        this.file = Paths.get(fileName);
    }

    /** Full location of the CSV file (shown on the history screen). */
    public String getFilePath() {
        return file.toAbsolutePath().toString();
    }

    /** Appends one scan to the CSV file. Returns false if the file could not be written. */
    public boolean addRecord(String scanType, int riskScore, String classification, String summary) {
        try {
            boolean needsHeader = !Files.exists(file) || Files.size(file) == 0;
            try (BufferedWriter writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                if (needsHeader) {
                    writer.write(HEADER);
                    writer.newLine();
                }
                String line = String.join(",",
                        quote(LocalDateTime.now().format(TIME_FORMAT)),
                        quote(scanType),
                        String.valueOf(riskScore),
                        quote(classification),
                        quote(summary));
                writer.write(line);
                writer.newLine();
            }
            return true;
        } catch (IOException e) {
            System.err.println("Could not save scan history: " + e.getMessage());
            return false;
        }
    }

    /** Reads all saved scans, oldest first. Broken lines are skipped. */
    public List<ScanRecord> loadAll() {
        List<ScanRecord> records = new ArrayList<>();
        if (!Files.exists(file)) {
            return records;
        }
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (String line : lines) {
                if (line.isBlank() || line.startsWith("DateTime,")) {
                    continue; // skip empty lines and the header
                }
                List<String> fields = parseLine(line);
                if (fields.size() < 5) {
                    continue;
                }
                try {
                    int score = Integer.parseInt(fields.get(2).trim());
                    records.add(new ScanRecord(fields.get(0), fields.get(1), score, fields.get(3), fields.get(4)));
                } catch (NumberFormatException ignored) {
                    // a damaged line - ignore it and keep reading
                }
            }
        } catch (IOException e) {
            System.err.println("Could not read scan history: " + e.getMessage());
        }
        return records;
    }

    /** Same as loadAll() but the newest scan comes first (used by tables and lists). */
    public List<ScanRecord> loadNewestFirst() {
        List<ScanRecord> records = loadAll();
        Collections.reverse(records);
        return records;
    }

    /** Deletes all scans but keeps the header line. */
    public boolean clearHistory() {
        try {
            Files.writeString(file, HEADER + System.lineSeparator(), StandardCharsets.UTF_8);
            return true;
        } catch (IOException e) {
            System.err.println("Could not clear scan history: " + e.getMessage());
            return false;
        }
    }

    // ------------------------------------------------------------------
    // CSV helpers
    // ------------------------------------------------------------------

    /** Wraps a value in quotes and doubles any quotes inside it. */
    private static String quote(String value) {
        String clean = value == null ? "" : value.replace("\r", " ").replace("\n", " ");
        return "\"" + clean.replace("\"", "\"\"") + "\"";
    }

    /** Splits one CSV line into fields, respecting quoted values. */
    private static List<String> parseLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean insideQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (insideQuotes) {
                if (c == '"') {
                    boolean escapedQuote = i + 1 < line.length() && line.charAt(i + 1) == '"';
                    if (escapedQuote) {
                        current.append('"');
                        i++;
                    } else {
                        insideQuotes = false;
                    }
                } else {
                    current.append(c);
                }
            } else if (c == '"') {
                insideQuotes = true;
            } else if (c == ',') {
                fields.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        fields.add(current.toString());
        return fields;
    }
}
