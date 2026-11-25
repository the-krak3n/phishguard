package com.phishguard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests the hybrid engine against a fake Gemini server running on localhost,
 * so no real API key or internet connection is needed.
 */
class HybridDetectorServiceTest {

    private static final String PAYPAL_SENDER = "security-alert@paypa1-support.xyz";
    private static final String PAYPAL_SUBJECT = "URGENT: Your account has been suspended!!!";
    private static final String PAYPAL_BODY = "Dear Customer, we detected unusual activity on your PayPal account and it has been "
            + "suspended. Verify your account within 24 hours: http://192.168.45.12/paypal/secure-login "
            + "Please enter your password and the OTP sent to your phone.";

    private final ObjectMapper mapper = new ObjectMapper();
    private HttpServer server;
    /** model name -> {status, gemini JSON answer text} */
    private final Map<String, Object[]> answers = new ConcurrentHashMap<>();
    private final List<String> requestPaths = new ArrayList<>();
    private final List<String> requestKeys = new ArrayList<>();
    private final List<JsonNode> requestBodies = new ArrayList<>();

    @BeforeEach
    void startFakeGemini() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1beta/models/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            synchronized (requestPaths) {
                requestPaths.add(exchange.getRequestURI().toString());
                requestKeys.add(exchange.getRequestHeaders().getFirst("x-goog-api-key"));
                try (InputStream in = exchange.getRequestBody()) {
                    requestBodies.add(mapper.readTree(in));
                }
            }
            String modelName = path.substring(path.lastIndexOf('/') + 1, path.indexOf(':'));
            Object[] answer = answers.getOrDefault(modelName, new Object[]{404, "{\"error\":{\"message\":\"model not found\"}}"});
            int status = (int) answer[0];
            String body = status == 200 ? wrapAsGeminiResponse((String) answer[1]) : (String) answer[1];
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
    }

    @AfterEach
    void stopFakeGemini() {
        server.stop(0);
    }

    private HybridDetectorService service(String apiKey, String fallbackModel) {
        String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1beta";
        GeminiClient client = new GeminiClient(apiKey, "gemini-2.5-flash", fallbackModel, baseUrl, 10, mapper);
        return new HybridDetectorService(client);
    }

    /** Puts the analysis JSON inside a generateContent response, as Gemini does. */
    private String wrapAsGeminiResponse(String analysisJson) throws IOException {
        Map<String, Object> part = Map.of("text", analysisJson);
        Map<String, Object> candidate = Map.of("content", Map.of("parts", List.of(part)), "finishReason", "STOP");
        return mapper.writeValueAsString(Map.of("candidates", List.of(candidate)));
    }

    @Test
    void offlineModeReturnsTheRuleEngineResult() {
        ScanResponse response = service("", "").scanEmail(PAYPAL_SENDER, PAYPAL_SUBJECT, PAYPAL_BODY);

        assertThat(response.engine).isEqualTo(ScanResponse.ENGINE_RULES);
        assertThat(response.aiScore).isNull();
        assertThat(response.result.score).isEqualTo(response.ruleScore).isEqualTo(100);
        assertThat(response.aiStatus).contains("GEMINI_API_KEY");
        assertThat(requestPaths).isEmpty();
    }

    @Test
    void emailScoreIsFortyPercentRulesPlusSixtyPercentGemini() {
        answers.put("gemini-2.5-flash", new Object[]{200, "{\"riskScore\":90,\"verdict\":\"Credential phishing posing as PayPal.\","
                + "\"indicators\":[{\"title\":\"Spoofed PayPal sender\",\"detail\":\"paypa1-support.xyz is not paypal.com\",\"severity\":\"high\"}],"
                + "\"recommendations\":[\"Do not click the link.\"]}"});

        ScanResponse response = service("test-key", "gemini-3.6-flash").scanEmail(PAYPAL_SENDER, PAYPAL_SUBJECT, PAYPAL_BODY);

        assertThat(response.engine).isEqualTo(ScanResponse.ENGINE_HYBRID);
        assertThat(response.ruleScore).isEqualTo(100);
        assertThat(response.aiScore).isEqualTo(90);
        assertThat(response.result.score).isEqualTo(94); // 0.4 * 100 + 0.6 * 90
        assertThat(response.result.classification).isEqualTo(PhishingDetector.HIGH_RISK);
        assertThat(response.result.indicators.get(0).category).isEqualTo("AI");
        assertThat(response.result.indicators.get(0).title).isEqualTo("Spoofed PayPal sender");
        assertThat(response.result.recommendations).contains("Do not click the link.");
        assertThat(response.result.notes.get(0)).contains("= 94");
        assertThat(response.model).isEqualTo("gemini-2.5-flash");

        // the request sent to Gemini
        assertThat(requestPaths.get(0)).isEqualTo("/v1beta/models/gemini-2.5-flash:generateContent");
        assertThat(requestKeys.get(0)).isEqualTo("test-key");
        JsonNode config = requestBodies.get(0).path("generationConfig");
        assertThat(config.path("responseMimeType").asText()).isEqualTo("application/json");
        assertThat(config.path("responseSchema").path("properties").has("riskScore")).isTrue();
        assertThat(requestBodies.get(0).toString()).contains("paypa1-support.xyz");
    }

    @Test
    void fallsBackToTheSecondModelWhenTheFirstIsUnavailable() {
        answers.put("gemini-3.6-flash", new Object[]{200, "{\"riskScore\":80,\"verdict\":\"Phishing.\",\"indicators\":[],\"recommendations\":[]}"});

        ScanResponse response = service("test-key", "gemini-3.6-flash").scanEmail(PAYPAL_SENDER, PAYPAL_SUBJECT, PAYPAL_BODY);

        assertThat(response.engine).isEqualTo(ScanResponse.ENGINE_HYBRID);
        assertThat(response.model).isEqualTo("gemini-3.6-flash");
        assertThat(response.result.notes).anyMatch(note -> note.contains("gemini-3.6-flash was used"));
        assertThat(requestPaths).hasSize(2);
    }

    @Test
    void geminiErrorFallsBackToTheRuleEngine() {
        answers.put("gemini-2.5-flash", new Object[]{429, "{\"error\":{\"code\":429,\"message\":\"Quota exceeded\"}}"});

        ScanResponse response = service("test-key", "gemini-3.6-flash").scanEmail(PAYPAL_SENDER, PAYPAL_SUBJECT, PAYPAL_BODY);

        assertThat(response.engine).isEqualTo(ScanResponse.ENGINE_RULES);
        assertThat(response.result.score).isEqualTo(100);
        assertThat(response.aiStatus).contains("Quota exceeded");
        assertThat(requestPaths).hasSize(1); // 429 is not a model problem, so no fallback model
    }

    @Test
    void imageIsSentInlineAndExtractedTextFeedsTheRuleEngine() throws IOException {
        answers.put("gemini-2.5-flash", new Object[]{200, "{\"extractedText\":\"ALERT: Your bank KYC has expired. Enter your card number, CVV and OTP immediately.\","
                + "\"detectedUrls\":[\"http://kyc-update-bank.top/login\"],\"riskScore\":95,\"verdict\":\"Smishing.\","
                + "\"indicators\":[{\"title\":\"Fake KYC alert\",\"detail\":\"Asks for card details\",\"severity\":\"HIGH\"}],\"recommendations\":[]}"});
        byte[] png;
        try (InputStream in = getClass().getResourceAsStream("/static/samples/images/1_high_risk_kyc_sms.png")) {
            png = in.readAllBytes();
        }

        ScanResponse response = service("test-key", "").scanImage(png, "image/png", "sms.png", null);

        JsonNode inline = requestBodies.get(0).path("contents").path(0).path("parts").path(0).path("inlineData");
        assertThat(inline.path("mimeType").asText()).isEqualTo("image/png");
        assertThat(inline.path("data").asText()).isNotEmpty();
        assertThat(response.extractedText).startsWith("ALERT: Your bank KYC");
        assertThat(response.ruleScore).isGreaterThanOrEqualTo(60); // rules ran on the AI-extracted text
        assertThat(response.result.urls).anyMatch(url -> url.url.contains("kyc-update-bank.top"));
        assertThat(response.result.score).isGreaterThanOrEqualTo(60);
    }

    @Test
    void audioIsTranscribedByGeminiAndTheTranscriptIsAnalysed() {
        answers.put("gemini-2.5-flash", new Object[]{200, "{\"transcript\":\"Caller: I am calling from your bank. Please share the OTP "
                + "you received and install AnyDesk now.\",\"riskScore\":92,\"verdict\":\"Vishing.\",\"indicators\":[],\"recommendations\":[]}"});

        ScanResponse response = service("test-key", "").scanVoice(new byte[]{1, 2, 3}, "audio/mp3", null, "+91 98XXX");

        assertThat(requestBodies.get(0).path("contents").path(0).path("parts").path(0).path("inlineData").path("mimeType").asText())
                .isEqualTo("audio/mp3");
        assertThat(response.transcript).contains("share the OTP");
        assertThat(response.ruleScore).isGreaterThan(30);
        assertThat(response.engine).isEqualTo(ScanResponse.ENGINE_HYBRID);
    }

    @Test
    void offlineImageWithoutTextAsksTheUserToTypeIt() {
        assertThatThrownBy(() -> service("", "").scanImage(new byte[]{1}, "image/png", "x.png", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("type the text");
    }
}
