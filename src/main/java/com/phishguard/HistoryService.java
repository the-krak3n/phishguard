package com.phishguard;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Thread-safe wrapper around {@link HistoryManager}.
 * A web server handles many requests at the same time, so every file access is synchronized.
 * The CSV location comes from app.history-file (environment variable HISTORY_FILE).
 */
@Service
public class HistoryService {

    private final HistoryManager manager;

    public HistoryService(@Value("${app.history-file:scan_history.csv}") String historyFile) {
        Path parent = Paths.get(historyFile).toAbsolutePath().getParent();
        try {
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create folder for the history file: " + parent, e);
        }
        this.manager = new HistoryManager(historyFile);
    }

    public synchronized boolean save(PhishingDetector.Result result) {
        return manager.addRecord(result.modality, result.score, result.classification, result.summary);
    }

    public synchronized List<HistoryManager.ScanRecord> loadAll() {
        return manager.loadAll();
    }

    public synchronized List<HistoryManager.ScanRecord> loadNewestFirst() {
        return manager.loadNewestFirst();
    }

    public synchronized boolean clear() {
        return manager.clearHistory();
    }
}
