package com.phishguard;

import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.SessionScope;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The latest Email, Image and Voice result of ONE browser session.
 * Used for the multimodal score. Each visitor gets their own copy (@SessionScope),
 * so two people using the deployed site do not mix their results.
 */
@Component
@SessionScope
public class LatestScans {

    private static final String[] MODALITIES = {PhishingDetector.EMAIL, PhishingDetector.IMAGE, PhishingDetector.VOICE};

    private final Map<String, PhishingDetector.Result> latest = new HashMap<>();

    public synchronized void remember(PhishingDetector.Result result) {
        latest.put(result.modality, result);
    }

    public synchronized PhishingDetector.Result get(String modality) {
        return latest.get(modality);
    }

    /** Available results in the order Email, Image, Voice. */
    public synchronized List<PhishingDetector.Result> available() {
        List<PhishingDetector.Result> list = new ArrayList<>();
        for (String modality : MODALITIES) {
            if (latest.containsKey(modality)) {
                list.add(latest.get(modality));
            }
        }
        return list;
    }

    public synchronized void clear() {
        latest.clear();
    }
}
