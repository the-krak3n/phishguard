package com.phishguard;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dashboard, multimodal and history endpoints:
 *   GET    /api/status             is Gemini active?
 *   GET    /api/dashboard          stats, scans per type, recent scans, live multimodal score
 *   POST   /api/multimodal/save    saves the combined score to the history
 *   POST   /api/multimodal/reset   forgets this session's latest scans
 *   GET    /api/history            all saved scans, newest first
 *   DELETE /api/history            clears the history file
 */
@RestController
@RequestMapping("/api")
public class DashboardController {

    private final HybridDetectorService detector;
    private final HistoryService history;
    private final LatestScans latestScans;

    public DashboardController(HybridDetectorService detector, HistoryService history, LatestScans latestScans) {
        this.detector = detector;
        this.history = history;
        this.latestScans = latestScans;
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("aiEnabled", detector.isAiEnabled());
        status.put("model", detector.isAiEnabled() ? detector.getModel() : null);
        status.put("mode", detector.isAiEnabled() ? "GEMINI_HYBRID" : "OFFLINE_RULES");
        status.put("blend", "40% rule engine + 60% Gemini");
        return status;
    }

    @GetMapping("/dashboard")
    public Map<String, Object> dashboard() {
        List<HistoryManager.ScanRecord> records = history.loadAll();
        int high = 0;
        int suspicious = 0;
        int safe = 0;
        Map<String, Integer> byType = new LinkedHashMap<>();
        for (String type : new String[]{PhishingDetector.EMAIL, PhishingDetector.IMAGE, PhishingDetector.VOICE, PhishingDetector.MULTIMODAL}) {
            byType.put(type, 0);
        }
        for (HistoryManager.ScanRecord record : records) {
            if (PhishingDetector.HIGH_RISK.equals(record.classification)) {
                high++;
            } else if (PhishingDetector.SUSPICIOUS.equals(record.classification)) {
                suspicious++;
            } else {
                safe++;
            }
            byType.merge(record.scanType, 1, Integer::sum);
        }

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("total", records.size());
        stats.put("high", high);
        stats.put("suspicious", suspicious);
        stats.put("safe", safe);

        List<HistoryManager.ScanRecord> recent = new ArrayList<>();
        for (int i = records.size() - 1; i >= 0 && recent.size() < 5; i--) {
            recent.add(records.get(i));
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status());
        body.put("stats", stats);
        body.put("byType", byType);
        body.put("recent", recent);
        body.put("multimodal", multimodal());
        return body;
    }

    @PostMapping("/multimodal/save")
    public PhishingDetector.Result saveMultimodal() {
        PhishingDetector.Result combined = PhishingDetector.combine(latestScans.available());
        if (combined == null) {
            throw new IllegalArgumentException("Run at least one scan before saving a multimodal report.");
        }
        history.save(combined);
        return combined;
    }

    @PostMapping("/multimodal/reset")
    public Map<String, Object> resetMultimodal() {
        latestScans.clear();
        return multimodal();
    }

    @GetMapping("/history")
    public List<HistoryManager.ScanRecord> historyList() {
        return history.loadNewestFirst();
    }

    @DeleteMapping("/history")
    public Map<String, Object> clearHistory() {
        if (!history.clear()) {
            throw new IllegalStateException("The history file could not be cleared.");
        }
        return Map.of("cleared", true);
    }

    /** Latest score per modality + the combined (average) result from PhishingDetector.combine(). */
    private Map<String, Object> multimodal() {
        List<PhishingDetector.Result> available = latestScans.available();
        PhishingDetector.Result combined = PhishingDetector.combine(available);

        Map<String, Object> scores = new LinkedHashMap<>();
        for (String modality : new String[]{PhishingDetector.EMAIL, PhishingDetector.IMAGE, PhishingDetector.VOICE}) {
            PhishingDetector.Result result = latestScans.get(modality);
            scores.put(modality, result == null ? null : result.score);
        }

        Map<String, Object> multimodal = new LinkedHashMap<>();
        multimodal.put("scores", scores);
        multimodal.put("combined", combined);
        if (combined != null) {
            List<String> numbers = new ArrayList<>();
            for (PhishingDetector.Result result : available) {
                numbers.add(String.valueOf(result.score));
            }
            multimodal.put("formula", "(" + String.join(" + ", numbers) + ") / " + available.size() + " = " + combined.score);
        }
        return multimodal;
    }
}
