package com.phishguard;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Runs the whole application (offline mode) and calls the REST API like the web page does. */
@SpringBootTest(properties = {"gemini.api-key=", "app.history-file=target/test-data/scan_history.csv"})
@AutoConfigureMockMvc
class ApiIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void fullScanFlowInOfflineMode() throws Exception {
        MockHttpSession session = new MockHttpSession();
        mvc.perform(delete("/api/history")).andExpect(status().isOk());

        mvc.perform(get("/api/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.aiEnabled").value(false))
                .andExpect(jsonPath("$.mode").value("OFFLINE_RULES"));

        mvc.perform(post("/api/scan/email").session(session).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sender\":\"security-alert@paypa1-support.xyz\",\"subject\":\"URGENT: account suspended\","
                                + "\"body\":\"Verify your account within 24 hours at http://192.168.45.12/login and enter your password and OTP.\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.engine").value("RULES"))
                .andExpect(jsonPath("$.classification").value("HIGH RISK"))
                .andExpect(jsonPath("$.indicators").isArray())
                .andExpect(jsonPath("$.urls[0].suspicious").value(true));

        mvc.perform(multipart("/api/scan/image").session(session)
                        .param("extractedText", "Your Netflix payment failed. Update your payment method: https://netflix-billing-help.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.modality").value("IMAGE"))
                .andExpect(jsonPath("$.score").value(34));

        mvc.perform(multipart("/api/scan/voice").session(session)
                        .param("transcript", "Hi, this is the clinic reminding you about your appointment tomorrow.")
                        .param("caller", "Clinic"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.classification").value("LOW RISK"));

        mvc.perform(get("/api/dashboard").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.stats.total").value(3))
                .andExpect(jsonPath("$.byType.IMAGE").value(1))
                .andExpect(jsonPath("$.multimodal.scores.IMAGE").value(34))
                .andExpect(jsonPath("$.multimodal.combined.modality").value("MULTIMODAL"))
                .andExpect(jsonPath("$.recent.length()").value(3));

        mvc.perform(post("/api/multimodal/save").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.modality").value("MULTIMODAL"));

        mvc.perform(get("/api/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].scanType").value("MULTIMODAL"))
                .andExpect(jsonPath("$[*].scanType", hasItem("EMAIL")));

        mvc.perform(post("/api/multimodal/reset").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.combined").value(nullValue()));

        mvc.perform(delete("/api/history")).andExpect(status().isOk());
        mvc.perform(get("/api/history")).andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void rejectsBadInput() throws Exception {
        MockMultipartFile textFile = new MockMultipartFile("image", "notes.txt", "text/plain", "hello".getBytes());
        mvc.perform(multipart("/api/scan/image").file(textFile))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());

        mvc.perform(post("/api/scan/email").contentType(MediaType.APPLICATION_JSON).content("{\"sender\":\"a@b.com\"}"))
                .andExpect(status().isBadRequest());

        MockMultipartFile audio = new MockMultipartFile("audio", "call.mp3", "audio/mpeg", new byte[]{1, 2, 3});
        mvc.perform(multipart("/api/scan/voice").file(audio))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(org.hamcrest.Matchers.containsString("transcript")));

        mvc.perform(get("/does-not-exist.png")).andExpect(status().isNotFound());
    }

    @Test
    void servesTheWebPage() throws Exception {
        mvc.perform(get("/index.html")).andExpect(status().isOk());
    }
}
