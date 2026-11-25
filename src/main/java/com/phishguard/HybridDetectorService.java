package com.phishguard;

import com.phishguard.GeminiClient.AiAnalysis;
import com.phishguard.GeminiClient.AiIndicator;
import com.phishguard.GeminiClient.GeminiException;
import com.phishguard.PhishingDetector.Indicator;
import com.phishguard.PhishingDetector.Result;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * HYBRID DETECTION ENGINE
 *
 * 1. The existing rule engine ({@link PhishingDetector}) always runs - it is fast, explainable and works offline.
 * 2. If GEMINI_API_KEY is set, Gemini also analyses the content (and reads images / transcribes audio).
 * 3. Both scores are blended:   final score = 40% rule score + 60% Gemini score.
 *    Indicators and recommendations from both engines are merged into one {@link Result}.
 *
 * If Gemini is not configured or fails, the rule-engine result is returned unchanged (automatic fallback).
 */
@Service
public class HybridDetectorService {

    public static final double RULE_WEIGHT = 0.4;
    public static final double AI_WEIGHT = 0.6;

    private final GeminiClient gemini;

    public HybridDetectorService(GeminiClient gemini) {
        this.gemini = gemini;
    }

    public boolean isAiEnabled() {
        return gemini.isEnabled();
    }

    public String getModel() {
        return gemini.getModel();
    }

    // =====================================================================
    // EMAIL
    // =====================================================================
    public ScanResponse scanEmail(String sender, String subject, String body) {
        Result rules = PhishingDetector.analyzeEmail(sender, subject, body);
        if (!gemini.isEnabled()) {
            return ScanResponse.rulesOnly(rules, offlineMessage(), null, null);
        }
        try {
            AiAnalysis ai = gemini.analyzeEmail(sender, subject, body);
            return blend(rules, ai, null, null);
        } catch (GeminiException e) {
            return ScanResponse.rulesOnly(rules, "Gemini unavailable - rule engine only: " + e.getMessage(), null, null);
        }
    }

    // =====================================================================
    // IMAGE
    // =====================================================================
    /**
     * @param image    image bytes (may be null if the user only typed text)
     * @param userText text the user typed from the image (optional)
     */
    public ScanResponse scanImage(byte[] image, String mimeType, String fileName, String userText) {
        AiAnalysis ai = null;
        String aiProblem = null;

        if (image != null && gemini.isEnabled()) {
            if (image.length > GeminiClient.MAX_INLINE_BYTES) {
                aiProblem = "Image is larger than 14 MB, too big to send to Gemini inline - rule engine only.";
            } else {
                try {
                    ai = gemini.analyzeImage(image, mimeType, userText);
                } catch (GeminiException e) {
                    aiProblem = "Gemini unavailable - rule engine only: " + e.getMessage();
                }
            }
        } else if (image == null && gemini.isEnabled() && !isBlank(userText)) {
            aiProblem = "No image uploaded - only the typed text was analysed by the rule engine.";
        }

        // Text for the rule engine = what Gemini read in the image (+ QR/visible URLs) + what the user typed.
        List<String> pieces = new ArrayList<>();
        if (ai != null) {
            pieces.add(ai.extractedText);
            pieces.add(String.join("\n", ai.detectedUrls));
        }
        if (ai == null || !contains(ai.extractedText, userText)) {
            pieces.add(userText);
        }
        String ruleText = joinNonBlank(pieces);

        if (ai == null && ruleText.isEmpty()) {
            String reason = !gemini.isEnabled()
                    ? "Offline mode cannot read images. Please type the text you can see in the image."
                    : aiProblem != null ? aiProblem + " Please type the text you can see in the image."
                    : "Please upload an image or type the text from it.";
            throw new IllegalArgumentException(reason);
        }

        Result rules = PhishingDetector.analyzeImageText(ruleText, fileName);
        if (ai == null) {
            return ScanResponse.rulesOnly(rules, aiProblem != null ? aiProblem : offlineMessage(), ruleText, null);
        }
        return blend(rules, ai, ai.extractedText, null);
    }

    // =====================================================================
    // VOICE
    // =====================================================================
    /**
     * @param audio      audio bytes (may be null if only a transcript was typed)
     * @param transcript typed transcript or notes (optional when audio is given)
     */
    public ScanResponse scanVoice(byte[] audio, String mimeType, String transcript, String caller) {
        AiAnalysis ai = null;
        String aiProblem = null;

        if (gemini.isEnabled()) {
            if (audio != null && audio.length > GeminiClient.MAX_INLINE_BYTES) {
                aiProblem = "Audio is larger than 14 MB, too big to send to Gemini inline - rule engine only.";
            } else if (audio != null || !isBlank(transcript)) {
                try {
                    ai = gemini.analyzeVoice(audio, mimeType, transcript, caller);
                } catch (GeminiException e) {
                    aiProblem = "Gemini unavailable - rule engine only: " + e.getMessage();
                }
            }
        }

        String aiTranscript = ai != null && audio != null ? ai.transcript : null;
        List<String> pieces = new ArrayList<>();
        pieces.add(aiTranscript);
        if (aiTranscript == null || !contains(aiTranscript, transcript)) {
            pieces.add(transcript);
        }
        String ruleText = joinNonBlank(pieces);

        if (ai == null && ruleText.isEmpty()) {
            String reason = !gemini.isEnabled()
                    ? "Offline mode cannot transcribe audio. Please type or paste the call transcript."
                    : aiProblem != null ? aiProblem + " Please type or paste the call transcript."
                    : "Please upload an audio file or type the call transcript.";
            throw new IllegalArgumentException(reason);
        }

        Result rules = PhishingDetector.analyzeVoiceTranscript(ruleText, caller);
        if (ai == null) {
            String status = aiProblem != null ? aiProblem
                    : audio != null ? "Offline mode: the audio was not transcribed; the typed transcript was analysed."
                    : offlineMessage();
            return ScanResponse.rulesOnly(rules, status, null, ruleText);
        }
        return blend(rules, ai, null, ruleText);
    }

    // =====================================================================
    // BLENDING
    // =====================================================================

    /** final = 40% rules + 60% Gemini; indicators, recommendations and notes are merged. */
    ScanResponse blend(Result rules, AiAnalysis ai, String extractedText, String transcript) {
        int score = (int) Math.round(RULE_WEIGHT * rules.score + AI_WEIGHT * ai.riskScore);

        List<Indicator> indicators = new ArrayList<>();
        for (AiIndicator aiIndicator : ai.indicators) {
            indicators.add(new Indicator("AI", aiIndicator.title, aiIndicator.detail, severityPoints(aiIndicator.severity)));
        }
        indicators.addAll(rules.indicators);

        Set<String> recommendations = new LinkedHashSet<>();
        for (String tip : ai.recommendations) {
            if (recommendations.size() < 4) {
                recommendations.add(tip.trim());
            }
        }
        recommendations.addAll(rules.recommendations);
        if (score >= 30) {
            recommendations.removeIf(tip -> tip.startsWith("No strong phishing signs"));
        }

        List<String> notes = new ArrayList<>();
        notes.add("Hybrid score = 40% x rule engine (" + rules.score + ") + 60% x Gemini (" + ai.riskScore + ") = " + score);
        if (ai.note != null) {
            notes.add(ai.note);
        }
        notes.addAll(rules.notes);

        String summary = rules.summary + (ai.verdict.isEmpty() ? "" : " | AI: " + shorten(ai.verdict, 90));
        Result blended = new Result(rules.modality, score, indicators, rules.urls,
                new ArrayList<>(recommendations), notes, summary);
        return new ScanResponse(blended, ScanResponse.ENGINE_HYBRID, rules.score, ai.riskScore, ai.verdict,
                ai.modelUsed, null, extractedText, transcript);
    }

    /** Points shown next to AI indicators (for display - the AI score itself comes from Gemini). */
    private static int severityPoints(String severity) {
        switch (severity.toUpperCase(Locale.ROOT)) {
            case "HIGH":
                return 15;
            case "LOW":
                return 4;
            default:
                return 8;
        }
    }

    private String offlineMessage() {
        return "Offline rule-engine mode (GEMINI_API_KEY is not set).";
    }

    private static boolean contains(String haystack, String needle) {
        if (isBlank(needle)) {
            return true;
        }
        if (isBlank(haystack)) {
            return false;
        }
        String normalizedHaystack = haystack.replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
        String normalizedNeedle = needle.replaceAll("\\s+", " ").toLowerCase(Locale.ROOT).trim();
        return normalizedHaystack.contains(normalizedNeedle);
    }

    private static String joinNonBlank(List<String> pieces) {
        StringBuilder builder = new StringBuilder();
        for (String piece : pieces) {
            if (!isBlank(piece)) {
                if (builder.length() > 0) {
                    builder.append("\n");
                }
                builder.append(piece.trim());
            }
        }
        return builder.toString();
    }

    private static String shorten(String text, int max) {
        return text.length() <= max ? text : text.substring(0, max - 3) + "...";
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
