package com.phishguard;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;

/**
 * Scan endpoints:
 *   POST /api/scan/email  JSON {sender, subject, body}
 *   POST /api/scan/image  multipart: image (PNG/JPG/WEBP) + optional extractedText
 *   POST /api/scan/voice  multipart: audio (MP3/WAV/OGG/M4A) and/or transcript + optional caller
 * Every result is saved to the CSV history and remembered for the multimodal score.
 */
@RestController
@RequestMapping("/api/scan")
public class ScanController {

    private static final Map<String, String> IMAGE_TYPES = Map.of(
            "png", "image/png", "jpg", "image/jpeg", "jpeg", "image/jpeg", "webp", "image/webp");

    private static final Map<String, String> AUDIO_TYPES = Map.of(
            "mp3", "audio/mp3", "wav", "audio/wav", "ogg", "audio/ogg", "m4a", "audio/m4a",
            "aac", "audio/aac", "flac", "audio/flac");

    private final HybridDetectorService detector;
    private final HistoryService history;
    private final LatestScans latestScans;

    public ScanController(HybridDetectorService detector, HistoryService history, LatestScans latestScans) {
        this.detector = detector;
        this.history = history;
        this.latestScans = latestScans;
    }

    public record EmailRequest(String sender, String subject, String body) {
    }

    @PostMapping(value = "/email", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ScanResponse scanEmail(@RequestBody EmailRequest request) {
        if (isBlank(request.subject()) && isBlank(request.body())) {
            throw new IllegalArgumentException("Please enter the email subject or content.");
        }
        return remember(detector.scanEmail(request.sender(), request.subject(), request.body()));
    }

    @PostMapping(value = "/image", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ScanResponse scanImage(@RequestParam(value = "image", required = false) MultipartFile image,
                                  @RequestParam(value = "extractedText", required = false) String extractedText)
            throws IOException {
        boolean hasImage = image != null && !image.isEmpty();
        if (!hasImage && isBlank(extractedText)) {
            throw new IllegalArgumentException("Please upload an image (PNG, JPG or WEBP) or type the text from it.");
        }
        byte[] bytes = null;
        String mimeType = null;
        String fileName = null;
        if (hasImage) {
            mimeType = mimeTypeOf(image, IMAGE_TYPES, "image", "PNG, JPG or WEBP");
            bytes = image.getBytes();
            fileName = image.getOriginalFilename();
        }
        return remember(detector.scanImage(bytes, mimeType, fileName, extractedText));
    }

    @PostMapping(value = "/voice", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ScanResponse scanVoice(@RequestParam(value = "audio", required = false) MultipartFile audio,
                                  @RequestParam(value = "transcript", required = false) String transcript,
                                  @RequestParam(value = "caller", required = false) String caller) throws IOException {
        boolean hasAudio = audio != null && !audio.isEmpty();
        if (!hasAudio && isBlank(transcript)) {
            throw new IllegalArgumentException("Please upload an audio file (MP3, WAV, OGG or M4A) or type the transcript.");
        }
        byte[] bytes = null;
        String mimeType = null;
        if (hasAudio) {
            mimeType = mimeTypeOf(audio, AUDIO_TYPES, "audio", "MP3, WAV, OGG or M4A");
            bytes = audio.getBytes();
        }
        return remember(detector.scanVoice(bytes, mimeType, transcript, caller));
    }

    private ScanResponse remember(ScanResponse response) {
        latestScans.remember(response.result);
        history.save(response.result);
        return response;
    }

    /** Works out the MIME type from the file extension (browsers do not always send a correct one). */
    private static String mimeTypeOf(MultipartFile file, Map<String, String> allowed, String kind, String allowedText) {
        String name = file.getOriginalFilename() == null ? "" : file.getOriginalFilename().toLowerCase(Locale.ROOT);
        String extension = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1) : "";
        if (allowed.containsKey(extension)) {
            return allowed.get(extension);
        }
        String contentType = file.getContentType() == null ? "" : file.getContentType().toLowerCase(Locale.ROOT);
        if (allowed.containsValue(contentType)) {
            return contentType;
        }
        throw new IllegalArgumentException("Unsupported " + kind + " file. Please use " + allowedText + ".");
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
