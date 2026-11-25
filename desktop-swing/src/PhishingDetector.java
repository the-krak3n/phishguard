import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PhishingDetector - the "brain" of the project.
 *
 * It is a RULE-BASED scoring engine. It does not use machine learning.
 * Instead it looks for well-known phishing tricks (urgent language, requests
 * for an OTP, fake links, spoofed senders ...) and adds points for each one.
 *
 *   score 0 - 29   -> LOW RISK
 *   score 30 - 59  -> SUSPICIOUS
 *   score 60 - 100 -> HIGH RISK
 *
 * Every point that is added is recorded as an "Indicator" so the user can see
 * exactly WHY a message received its score.
 *
 * Safety rules so that one word never makes a message "dangerous":
 *   - Only ONE thing found in total        -> score is limited to 20 (LOW RISK)
 *   - Everything found is in ONE category  -> score is limited to 45 (SUSPICIOUS)
 */
public class PhishingDetector {

    // ---------------------------------------------------------------------
    // Constants used everywhere in the app
    // ---------------------------------------------------------------------
    public static final String EMAIL = "EMAIL";
    public static final String IMAGE = "IMAGE";
    public static final String VOICE = "VOICE";
    public static final String MULTIMODAL = "MULTIMODAL";

    public static final String LOW_RISK = "LOW RISK";
    public static final String SUSPICIOUS = "SUSPICIOUS";
    public static final String HIGH_RISK = "HIGH RISK";

    /** Extra points for every additional keyword found in the same category. */
    private static final int EXTRA_KEYWORD_POINTS = 5;
    /** Maximum points that all link problems together can add. */
    private static final int MAX_URL_POINTS = 35;
    /** Maximum points that all sender problems together can add. */
    private static final int MAX_SENDER_POINTS = 25;

    // =====================================================================
    // 1. RESULT DATA CLASSES
    // =====================================================================

    /** One reason why the score went up (or down). */
    public static class Indicator {
        public final String category; // e.g. "OTP", "URL", "SENDER", "COMBO"
        public final String title;    // short name, e.g. "OTP request"
        public final String detail;   // what exactly was found
        public final int points;      // how many points it added (negative = lowered the score)

        public Indicator(String category, String title, String detail, int points) {
            this.category = category;
            this.title = title;
            this.detail = detail;
            this.points = points;
        }
    }

    /** A link found in the text and the problems found with it. */
    public static class UrlFinding {
        public final String url;
        public final List<String> issues = new ArrayList<>();

        public UrlFinding(String url) {
            this.url = url;
        }

        public boolean isSuspicious() {
            return !issues.isEmpty();
        }
    }

    /** The complete answer returned after a scan. */
    public static class Result {
        public final String modality;            // EMAIL, IMAGE, VOICE or MULTIMODAL
        public final int score;                  // 0 - 100
        public final String classification;      // LOW RISK, SUSPICIOUS, HIGH RISK
        public final List<Indicator> indicators; // reasons for the score
        public final List<UrlFinding> urls;      // links found in the text
        public final List<String> recommendations;
        public final List<String> notes;         // extra explanations (caps, averages ...)
        public final String summary;             // one line, saved in the history file

        public Result(String modality, int score, List<Indicator> indicators, List<UrlFinding> urls,
                      List<String> recommendations, List<String> notes, String summary) {
            this.modality = modality;
            this.score = score;
            this.classification = classify(score);
            this.indicators = indicators;
            this.urls = urls;
            this.recommendations = recommendations;
            this.notes = notes;
            this.summary = summary;
        }

        /** Number of reasons that increased the score. */
        public int positiveIndicatorCount() {
            int count = 0;
            for (Indicator indicator : indicators) {
                if (indicator.points > 0) {
                    count++;
                }
            }
            return count;
        }

        public int suspiciousUrlCount() {
            int count = 0;
            for (UrlFinding url : urls) {
                if (url.isSuspicious()) {
                    count++;
                }
            }
            return count;
        }
    }

    // =====================================================================
    // 2. KEYWORD RULES
    // =====================================================================

    /**
     * A Rule is one category of phishing trick with its keywords.
     * First keyword found = baseWeight points, each extra keyword = +5,
     * but never more than maxWeight.
     */
    private static class Rule {
        final String id;
        final String title;
        final int baseWeight;
        final int maxWeight;
        final String[] keywords;
        final Pattern[] patterns;

        Rule(String id, String title, int baseWeight, int maxWeight, String... keywords) {
            this.id = id;
            this.title = title;
            this.baseWeight = baseWeight;
            this.maxWeight = maxWeight;
            this.keywords = keywords;
            this.patterns = new Pattern[keywords.length];
            for (int i = 0; i < keywords.length; i++) {
                // Match whole words only, so "pin" does not match "spinning".
                patterns[i] = Pattern.compile("(?<![a-z0-9])" + Pattern.quote(keywords[i]) + "(?![a-z0-9])",
                        Pattern.CASE_INSENSITIVE);
            }
        }
    }

    private static final Rule URGENCY = new Rule("URGENCY", "Urgency / pressure language", 10, 20,
            "urgent", "urgently", "immediately", "immediate action", "act now", "right now", "right away",
            "asap", "as soon as possible", "within 24 hours", "within 48 hours", "within 12 hours",
            "within 2 hours", "final notice", "final warning", "last warning", "last chance",
            "expires today", "expire today", "limited time", "today only", "hurry", "do it now", "quickly");

    private static final Rule CREDENTIALS = new Rule("CREDENTIALS", "Password / credential request", 18, 28,
            "password", "passcode", "username", "user id", "login credentials", "login details",
            "credentials", "security question", "mother's maiden name");

    private static final Rule OTP = new Rule("OTP", "OTP / verification code request", 20, 30,
            "otp", "one time password", "one-time password", "verification code", "security code",
            "authentication code", "6 digit code", "6-digit code", "sms code");

    private static final Rule PIN = new Rule("PIN", "PIN request", 18, 26,
            "pin", "atm pin", "upi pin", "mpin", "pin number", "card pin");

    private static final Rule BANK_DETAILS = new Rule("BANK_DETAILS", "Bank / card details request", 18, 30,
            "account number", "bank account", "card number", "credit card", "debit card", "cvv",
            "expiry date", "ifsc", "bank details", "card details", "net banking", "netbanking",
            "routing number", "aadhaar", "pan card", "social security number");

    private static final Rule PAYMENT = new Rule("PAYMENT", "Payment / money request", 12, 24,
            "payment", "pay now", "make a payment", "wire transfer", "bank transfer", "money transfer",
            "send money", "transfer the amount", "gift card", "gift cards", "processing fee", "transfer fee",
            "registration fee", "delivery charge", "service charge", "advance fee", "pay only",
            "outstanding balance", "pay a fine", "upi", "paytm", "google pay");

    private static final Rule SUSPENSION = new Rule("SUSPENSION", "Account suspension threat", 14, 24,
            "suspend", "suspended", "suspension", "deactivate", "deactivated", "locked", "blocked",
            "closed permanently", "permanently closed", "terminated", "restricted", "disabled",
            "unusual activity", "suspicious activity", "unauthorized", "unauthorised", "security breach",
            "compromised", "will be closed", "has expired", "kyc expired");

    private static final Rule PRIZE = new Rule("PRIZE", "Fake prize / lottery", 15, 30,
            "congratulations", "you have won", "you've won", "you won", "winner", "lottery", "prize",
            "jackpot", "reward", "free gift", "claim your", "claim now", "lucky draw", "selected for",
            "cash prize", "gift voucher");

    private static final Rule FRAUD_OFFER = new Rule("FRAUD_OFFER", "Too-good-to-be-true offer", 10, 22,
            "100% free", "free iphone", "limited offer", "exclusive offer", "cashback", "90% off",
            "guaranteed", "work from home", "earn money", "earn daily", "no investment", "bonus",
            "double your");

    private static final Rule SUSPICIOUS_CTA = new Rule("SUSPICIOUS_CTA", "Suspicious call-to-action", 10, 18,
            "click here", "click the link", "click below", "click on the link", "tap here", "tap the link",
            "verify now", "login now", "log in now", "update now", "confirm now", "follow the link",
            "open the attachment", "download the attachment");

    private static final Rule FAKE_LOGIN = new Rule("FAKE_LOGIN", "Fake login / verification request", 12, 22,
            "log in to", "login to", "sign in to", "login here", "login page", "session expired",
            "session has expired", "re-enter", "verify your account", "verify your identity",
            "confirm your identity", "confirm your account", "update your account", "update your details",
            "validate your account", "account verification", "update kyc", "complete your kyc");

    private static final Rule IMPERSONATION = new Rule("IMPERSONATION", "Generic greeting / impersonation", 8, 16,
            "dear customer", "dear valued customer", "dear user", "dear account holder", "dear member",
            "dear client", "security team", "support team", "it department", "help desk", "helpdesk",
            "customer care", "billing department", "account department", "official notice");

    private static final Rule AUTHORITY = new Rule("AUTHORITY", "Fake bank / government representative", 14, 26,
            "calling from", "bank manager", "bank officer", "from your bank", "head office", "reserve bank",
            "rbi", "income tax", "tax department", "customs", "cyber cell", "cyber crime", "police",
            "government", "ministry", "court", "fedex", "courier", "microsoft", "technical support",
            "tech support", "kyc", "telecom department");

    private static final Rule THREATS = new Rule("THREATS", "Threats / intimidation", 16, 28,
            "arrest", "arrested", "warrant", "legal action", "legal case", "jail", "prison", "case registered",
            "case will be filed", "fir", "penalty", "lawsuit", "seized", "frozen", "freeze your",
            "disconnected", "if you do not cooperate");

    private static final Rule REMOTE_ACCESS = new Rule("REMOTE_ACCESS", "Remote access app request", 22, 32,
            "anydesk", "any desk", "teamviewer", "team viewer", "quicksupport", "quick support",
            "remote access", "screen share", "screen sharing", "share your screen", "install this app",
            "download this app", "download the app", "rustdesk", "ultraviewer", "apk");

    private static final Rule INVESTMENT = new Rule("INVESTMENT", "Fraudulent investment claim", 14, 30,
            "guaranteed returns", "guaranteed profit", "double your money", "doubled their money",
            "high returns", "risk free", "risk-free", "investment opportunity", "invest now",
            "trading platform", "crypto", "bitcoin", "forex", "every month", "daily profit", "stock tips");

    /** Which rules are used for each type of scan. */
    private static final Rule[] EMAIL_RULES = {
            URGENCY, CREDENTIALS, OTP, PIN, BANK_DETAILS, PAYMENT, SUSPENSION, PRIZE,
            SUSPICIOUS_CTA, FAKE_LOGIN, IMPERSONATION
    };
    private static final Rule[] IMAGE_RULES = {
            URGENCY, CREDENTIALS, OTP, PIN, BANK_DETAILS, PAYMENT, FAKE_LOGIN, PRIZE,
            FRAUD_OFFER, SUSPICIOUS_CTA, SUSPENSION
    };
    private static final Rule[] VOICE_RULES = {
            URGENCY, OTP, PIN, CREDENTIALS, BANK_DETAILS, PAYMENT, REMOTE_ACCESS, THREATS,
            AUTHORITY, INVESTMENT, SUSPENSION
    };

    /** "Send me your OTP" style sentences: an action word followed by a secret. */
    private static final Pattern SENSITIVE_REQUEST = Pattern.compile(
            "\\b(share|send|tell|give|provide|enter|type|confirm|verify|read out|forward|submit|reply with|"
                    + "update|disclose|say)\\b[^.!?]{0,25}?\\b(otp|one[- ]time password|password|passcode|pin|cvv|"
                    + "verification code|security code|card number|account number|bank details|login details|"
                    + "credentials)\\b",
            Pattern.CASE_INSENSITIVE);

    /** Phrases that genuine messages use to warn people. They lower the score a little. */
    private static final String[] SAFETY_PHRASES = {
            "never share", "do not share", "don't share", "dont share", "will never ask",
            "never ask for your", "we never ask", "do not disclose", "never disclose"
    };

    // =====================================================================
    // 3. URL AND SENDER DATA
    // =====================================================================

    private static final String URL_CHARS = "[^\\s<>\"'()\\[\\]{}]";
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(?i)(?:https?://|www\\.)" + URL_CHARS + "+"                                   // http://..., www...
                    + "|(?<![\\w.])\\d{1,3}(?:\\.\\d{1,3}){3}(?::\\d+)?(?:/" + URL_CHARS + "*)?"  // 192.168.1.5/login
                    + "|(?<![@\\w.-])[a-z0-9][a-z0-9-]*(?:\\.[a-z0-9-]+)*\\."                 // paypal-login.top/...
                    + "(?:com|net|org|info|biz|xyz|top|online|site|club|live|click|link|io|co|in|me|app|shop|"
                    + "store|support|help|win|loan|work|ly|gl|gd|cc|at|icu|buzz)\\b(?:/" + URL_CHARS + "*)?");

    private static final Pattern IP_ADDRESS = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern EMAIL_FORMAT = Pattern.compile("^[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}$");

    private static final Set<String> SHORTENERS = new HashSet<>(List.of(
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rb.gy", "cutt.ly",
            "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "s.id"));

    private static final Set<String> RISKY_TLDS = new HashSet<>(List.of(
            "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "loan", "win", "zip",
            "mov", "icu", "buzz", "rest", "cam", "monster", "online", "site", "live", "support"));

    private static final Set<String> FREE_EMAIL_DOMAINS = new HashSet<>(List.of(
            "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "mail.com", "protonmail.com",
            "yandex.com", "gmx.com", "rediffmail.com", "icloud.com", "live.com", "ymail.com"));

    private static final String[] URL_BAIT_WORDS = {
            "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
            "banking", "confirm", "wallet", "password", "unlock", "kyc", "reward", "claim", "free"
    };

    /** Well-known brands and their real (official) domains. */
    private static final Map<String, String[]> BRAND_DOMAINS = new LinkedHashMap<>();

    static {
        BRAND_DOMAINS.put("paypal", new String[]{"paypal.com"});
        BRAND_DOMAINS.put("amazon", new String[]{"amazon.com", "amazon.in", "amazon.co.uk"});
        BRAND_DOMAINS.put("apple", new String[]{"apple.com", "icloud.com"});
        BRAND_DOMAINS.put("microsoft", new String[]{"microsoft.com", "live.com", "outlook.com", "office.com"});
        BRAND_DOMAINS.put("google", new String[]{"google.com", "gmail.com", "youtube.com"});
        BRAND_DOMAINS.put("netflix", new String[]{"netflix.com"});
        BRAND_DOMAINS.put("facebook", new String[]{"facebook.com", "fb.com"});
        BRAND_DOMAINS.put("instagram", new String[]{"instagram.com"});
        BRAND_DOMAINS.put("whatsapp", new String[]{"whatsapp.com"});
        BRAND_DOMAINS.put("linkedin", new String[]{"linkedin.com"});
        BRAND_DOMAINS.put("hdfc", new String[]{"hdfcbank.com"});
        BRAND_DOMAINS.put("icici", new String[]{"icicibank.com"});
        BRAND_DOMAINS.put("sbi", new String[]{"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"});
        BRAND_DOMAINS.put("paytm", new String[]{"paytm.com"});
        BRAND_DOMAINS.put("fedex", new String[]{"fedex.com"});
        BRAND_DOMAINS.put("dhl", new String[]{"dhl.com"});
    }

    /** Link problems and how many points each one adds (counted once per scan). */
    private static final Map<String, Integer> URL_ISSUE_POINTS = new LinkedHashMap<>();

    static {
        URL_ISSUE_POINTS.put("IP-based URL", 18);
        URL_ISSUE_POINTS.put("Brand look-alike link", 16);
        URL_ISSUE_POINTS.put("URL shortener", 12);
        URL_ISSUE_POINTS.put("Hidden '@' in link", 12);
        URL_ISSUE_POINTS.put("High-risk domain ending", 10);
        URL_ISSUE_POINTS.put("Bait words in link", 8);
        URL_ISSUE_POINTS.put("Complex or very long link", 6);
        URL_ISSUE_POINTS.put("Insecure HTTP link", 5);
    }

    // =====================================================================
    // 4. PUBLIC METHODS - one per modality + the multimodal combination
    // =====================================================================

    /** Analyses an email using its sender, subject and body. */
    public static Result analyzeEmail(String sender, String subject, String body) {
        String text = safe(subject) + "\n" + safe(body);
        Analysis analysis = new Analysis();

        applyKeywordRules(analysis, text, EMAIL_RULES);
        applySensitiveRequestCheck(analysis, text);
        applyFormattingCheck(analysis, text);
        applyUrlChecks(analysis, text);
        applySenderChecks(analysis, sender, text);
        applySafetyLanguage(analysis, text);
        applyCombinationBonuses(analysis);

        String from = safe(sender).isBlank() ? "unknown sender" : sender.trim();
        String subjectPart = safe(subject).isBlank() ? "" : " \"" + shorten(subject.trim(), 40) + "\"";
        return buildResult(EMAIL, analysis, "Email from " + from + subjectPart);
    }

    /** Analyses the text that the user typed from an image (screenshot, poster, SMS ...). */
    public static Result analyzeImageText(String extractedText, String imageName) {
        String text = safe(extractedText);
        Analysis analysis = new Analysis();

        applyKeywordRules(analysis, text, IMAGE_RULES);
        applySensitiveRequestCheck(analysis, text);
        applyFormattingCheck(analysis, text);
        applyUrlChecks(analysis, text);
        applySafetyLanguage(analysis, text);
        applyCombinationBonuses(analysis);

        String context = imageName == null || imageName.isBlank()
                ? "Image text (no image attached)" : "Image " + shorten(imageName, 40);
        return buildResult(IMAGE, analysis, context);
    }

    /** Analyses the transcript of a phone call. */
    public static Result analyzeVoiceTranscript(String transcript, String caller) {
        String text = safe(transcript);
        Analysis analysis = new Analysis();

        applyKeywordRules(analysis, text, VOICE_RULES);
        applySensitiveRequestCheck(analysis, text);
        applySafetyLanguage(analysis, text);
        applyCombinationBonuses(analysis);

        int words = text.isBlank() ? 0 : text.trim().split("\\s+").length;
        String who = safe(caller).isBlank() ? "unknown caller" : shorten(caller.trim(), 30);
        return buildResult(VOICE, analysis, "Call from " + who + " (" + words + " words)");
    }

    /**
     * MULTIMODAL ANALYSIS: combines the latest results of each modality.
     * Overall score = simple average of the available modality scores.
     * Returns null when no results are given.
     */
    public static Result combine(List<Result> results) {
        if (results == null || results.isEmpty()) {
            return null;
        }
        int sum = 0;
        List<String> parts = new ArrayList<>();
        List<String> modalityNames = new ArrayList<>();
        List<Indicator> merged = new ArrayList<>();
        List<UrlFinding> urls = new ArrayList<>();
        Set<String> recommendations = new LinkedHashSet<>();

        for (Result result : results) {
            sum += result.score;
            parts.add(displayName(result.modality) + " " + result.score);
            modalityNames.add(displayName(result.modality));
            for (Indicator indicator : result.indicators) {
                if (indicator.points > 0) {
                    merged.add(new Indicator(indicator.category,
                            displayName(result.modality) + ": " + indicator.title, indicator.detail, indicator.points));
                }
            }
            urls.addAll(result.urls);
            recommendations.addAll(result.recommendations);
        }

        int overall = Math.round((float) sum / results.size());
        merged.sort(Comparator.comparingInt((Indicator i) -> i.points).reversed());

        if (overall >= 30) {
            recommendations.removeIf(r -> r.startsWith("No strong phishing signs"));
        }

        List<String> notes = new ArrayList<>();
        notes.add("Overall score = average of " + String.join(", ", parts) + " = " + overall);
        if (results.size() == 1) {
            notes.add("Only one modality was scanned, so the overall score equals that score.");
        }

        String summary = "Combined " + String.join(" + ", modalityNames) + " - " + topTitles(merged, 3);
        return new Result(MULTIMODAL, overall, merged, urls, new ArrayList<>(recommendations), notes, summary);
    }

    /** Turns a score into a classification label. */
    public static String classify(int score) {
        if (score >= 60) {
            return HIGH_RISK;
        }
        if (score >= 30) {
            return SUSPICIOUS;
        }
        return LOW_RISK;
    }

    /** "EMAIL" -> "Email" (used for display). */
    public static String displayName(String modality) {
        switch (modality) {
            case EMAIL:
                return "Email";
            case IMAGE:
                return "Image";
            case VOICE:
                return "Voice";
            case MULTIMODAL:
                return "Multimodal";
            default:
                return modality;
        }
    }

    // =====================================================================
    // 5. ANALYSIS STEPS
    // =====================================================================

    /** Collects everything that was found while one message is analysed. */
    private static class Analysis {
        final List<Indicator> indicators = new ArrayList<>();
        final List<UrlFinding> urls = new ArrayList<>();
        final List<String> notes = new ArrayList<>();
        final Set<String> categories = new LinkedHashSet<>(); // categories with real evidence
        int signalCount = 0;                                   // how many separate things were found

        void add(String category, String title, String detail, int points, int signals) {
            indicators.add(new Indicator(category, title, detail, points));
            boolean isEvidence = points > 0 && !category.equals("COMBO");
            if (isEvidence) {
                categories.add(category);
                signalCount += signals;
            }
        }

        boolean has(String... wanted) {
            for (String category : wanted) {
                if (categories.contains(category)) {
                    return true;
                }
            }
            return false;
        }

        int totalPoints() {
            int total = 0;
            for (Indicator indicator : indicators) {
                total += indicator.points;
            }
            return total;
        }
    }

    /** Step 1: look for the keywords of every rule. */
    private static void applyKeywordRules(Analysis analysis, String text, Rule[] rules) {
        String clean = normalize(text);
        for (Rule rule : rules) {
            List<String> found = new ArrayList<>();
            for (int i = 0; i < rule.patterns.length; i++) {
                if (rule.patterns[i].matcher(clean).find()) {
                    found.add(rule.keywords[i]);
                }
            }
            if (!found.isEmpty()) {
                int points = Math.min(rule.maxWeight, rule.baseWeight + EXTRA_KEYWORD_POINTS * (found.size() - 1));
                analysis.add(rule.id, rule.title, "Found " + quoteList(found, 4), points, found.size());
            }
        }
    }

    /** Step 2: sentences that directly ask for a secret, e.g. "share the OTP with me". */
    private static void applySensitiveRequestCheck(Analysis analysis, String text) {
        // Remove links and treat every new line as the end of a sentence.
        String withoutUrls = URL_PATTERN.matcher(safe(text)).replaceAll(" ");
        String clean = normalize(withoutUrls.replace("\n", ". "));
        Matcher matcher = SENSITIVE_REQUEST.matcher(clean);
        Set<String> phrases = new LinkedHashSet<>();
        while (matcher.find()) {
            // Ignore warnings like "do NOT share your OTP".
            String before = clean.substring(Math.max(0, matcher.start() - 15), matcher.start());
            if (before.contains("not ") || before.contains("never") || before.contains("n't") || before.contains("dont")) {
                continue;
            }
            phrases.add(matcher.group().trim());
        }
        if (!phrases.isEmpty()) {
            int points = Math.min(25, 15 + EXTRA_KEYWORD_POINTS * (phrases.size() - 1));
            analysis.add("SENSITIVE_REQUEST", "Direct request for secret information",
                    "Phrase " + quoteList(new ArrayList<>(phrases), 2), points, phrases.size());
        }
    }

    /** Step 3: shouting in CAPITALS and lots of exclamation marks!!! */
    private static void applyFormattingCheck(Analysis analysis, String text) {
        String withoutUrls = URL_PATTERN.matcher(text).replaceAll(" ");
        int exclamations = 0;
        for (char c : withoutUrls.toCharArray()) {
            if (c == '!') {
                exclamations++;
            }
        }
        Set<String> ignore = Set.of("HTTP", "HTTPS", "HTML", "JPEG", "KYC", "OTP", "CVV", "IFSC", "UPI", "ATM", "USD", "INR");
        List<String> capsWords = new ArrayList<>();
        Matcher caps = Pattern.compile("\\b[A-Z]{4,}\\b").matcher(withoutUrls);
        while (caps.find()) {
            if (!ignore.contains(caps.group())) {
                capsWords.add(caps.group());
            }
        }

        List<String> details = new ArrayList<>();
        if (exclamations >= 3) {
            details.add(exclamations + " exclamation marks");
        }
        if (capsWords.size() >= 3) {
            details.add(capsWords.size() + " words in CAPITALS");
        }
        if (!details.isEmpty()) {
            analysis.add("FORMATTING", "Aggressive formatting", String.join(", ", details),
                    details.size() == 2 ? 8 : 4, details.size());
        }
    }

    /** Step 4: find links and check each one for common phishing tricks. */
    private static void applyUrlChecks(Analysis analysis, String text) {
        Map<String, String> issueExamples = new LinkedHashMap<>(); // issue title -> example URL

        for (String url : extractUrls(text)) {
            UrlFinding finding = new UrlFinding(url);
            String lower = url.toLowerCase(Locale.ROOT);
            String host = extractHost(url);
            String authority = lower.replaceFirst("^[a-z]+://", "").split("[/?#]", 2)[0];
            String tld = host.contains(".") ? host.substring(host.lastIndexOf('.') + 1) : "";

            if (IP_ADDRESS.matcher(host).matches()) {
                flag(finding, issueExamples, "IP-based URL", "uses a raw IP address instead of a website name");
            }
            String brand = findImpersonatedBrand(host);
            if (brand != null) {
                flag(finding, issueExamples, "Brand look-alike link", "pretends to be " + capitalize(brand) + " but is not its official website");
            }
            if (SHORTENERS.contains(host)) {
                flag(finding, issueExamples, "URL shortener", "shortened link hides the real destination");
            }
            if (authority.contains("@")) {
                flag(finding, issueExamples, "Hidden '@' in link", "contains '@', which can disguise the real website");
            }
            if (RISKY_TLDS.contains(tld)) {
                flag(finding, issueExamples, "High-risk domain ending", "uses the high-risk domain ending ." + tld);
            }
            List<String> bait = new ArrayList<>();
            for (String word : URL_BAIT_WORDS) {
                if (lower.contains(word) && bait.size() < 3) {
                    bait.add(word);
                }
            }
            if (!bait.isEmpty() && !SHORTENERS.contains(host)) {
                flag(finding, issueExamples, "Bait words in link", "contains bait words: " + String.join(", ", bait));
            }
            if (countChar(host, '-') >= 2 || countChar(host, '.') >= 4 || url.length() > 75) {
                flag(finding, issueExamples, "Complex or very long link", "unusually long or complicated address");
            }
            if (lower.startsWith("http://")) {
                flag(finding, issueExamples, "Insecure HTTP link", "not encrypted (HTTP instead of HTTPS)");
            }
            analysis.urls.add(finding);
        }

        // Score each type of problem once, up to MAX_URL_POINTS in total.
        int used = 0;
        for (Map.Entry<String, Integer> issue : URL_ISSUE_POINTS.entrySet()) {
            if (issueExamples.containsKey(issue.getKey())) {
                int points = Math.min(issue.getValue(), MAX_URL_POINTS - used);
                if (points <= 0) {
                    break; // limit reached - the problem is still listed under "Detected URLs"
                }
                used += points;
                String detail = "Seen in " + shorten(issueExamples.get(issue.getKey()), 60)
                        + (points < issue.getValue() ? " (link limit of " + MAX_URL_POINTS + " points reached)" : "");
                analysis.add("URL", issue.getKey(), detail, points, 1);
            }
        }
    }

    /** Step 5 (email only): check the sender address. */
    private static void applySenderChecks(Analysis analysis, String sender, String text) {
        if (safe(sender).isBlank()) {
            analysis.notes.add("No sender address was given, so the sender checks were skipped.");
            return;
        }
        String address = sender.trim().toLowerCase(Locale.ROOT);
        int open = address.indexOf('<');
        int close = address.indexOf('>');
        if (open >= 0 && close > open) {              // supports "Name <name@example.com>"
            address = address.substring(open + 1, close).trim();
        }

        List<Indicator> found = new ArrayList<>();
        if (!EMAIL_FORMAT.matcher(address).matches()) {
            found.add(new Indicator("SENDER", "Invalid sender address", "\"" + sender.trim() + "\" is not a valid email address", 12));
        } else {
            String localPart = address.substring(0, address.indexOf('@'));
            String domain = address.substring(address.indexOf('@') + 1);
            String tld = domain.substring(domain.lastIndexOf('.') + 1);
            String brand = findImpersonatedBrand(domain);
            String mentionedBrand = findMentionedBrand(text);
            boolean freeEmail = FREE_EMAIL_DOMAINS.contains(domain);
            boolean officialSoundingName = containsAny(localPart, "support", "security", "admin", "service", "billing",
                    "alert", "verify", "helpdesk", "bank", "account", "team", "official", "update", "reward");

            if (brand != null) {
                found.add(new Indicator("SENDER", "Look-alike sender domain",
                        domain + " pretends to be " + capitalize(brand) + " but is not its official domain", 18));
            }
            boolean freeEmailFlagged = false;
            if (freeEmail && (officialSoundingName || mentionedBrand != null || analysis.has("IMPERSONATION"))) {
                found.add(new Indicator("SENDER", "Free email posing as an organisation",
                        "Official-looking message sent from a free " + domain + " account", 12));
                freeEmailFlagged = true;
            }
            if (RISKY_TLDS.contains(tld)) {
                found.add(new Indicator("SENDER", "High-risk sender domain", "Sender domain ends with ." + tld, 10));
            }
            if (countDigits(localPart) >= 4) {
                found.add(new Indicator("SENDER", "Random-looking sender name", "\"" + localPart + "\" contains many numbers", 6));
            }
            boolean asksForSomething = analysis.has("CREDENTIALS", "OTP", "FAKE_LOGIN", "SUSPENSION", "PAYMENT", "BANK_DETAILS");
            if (brand == null && !freeEmailFlagged && mentionedBrand != null && !isOfficialDomain(domain, mentionedBrand) && asksForSomething) {
                found.add(new Indicator("SENDER", "Brand / sender mismatch",
                        "Message mentions " + capitalize(mentionedBrand) + " but was sent from " + domain, 10));
            }
        }

        int used = 0;
        for (Indicator indicator : found) {
            int points = Math.min(indicator.points, MAX_SENDER_POINTS - used);
            if (points <= 0) {
                break; // sender limit reached
            }
            used += points;
            analysis.add(indicator.category, indicator.title, indicator.detail, points, 1);
        }
    }

    /** Step 6: genuine messages often warn "never share your OTP" - lower the score a bit. */
    private static void applySafetyLanguage(Analysis analysis, String text) {
        String clean = normalize(text);
        List<String> found = new ArrayList<>();
        for (String phrase : SAFETY_PHRASES) {
            if (clean.contains(phrase)) {
                found.add(phrase);
            }
        }
        if (!found.isEmpty()) {
            analysis.add("SAFETY", "Genuine safety advice", "Found " + quoteList(found, 2)
                    + " - common in real messages", -10, 0);
        }
    }

    /** Step 7: dangerous COMBINATIONS of tricks add bonus points. */
    private static void applyCombinationBonuses(Analysis analysis) {
        int categoryCount = analysis.categories.size();
        boolean pressure = analysis.has("URGENCY", "SUSPENSION", "THREATS");
        boolean asksForSecrets = analysis.has("CREDENTIALS", "OTP", "PIN", "BANK_DETAILS", "SENSITIVE_REQUEST");

        if (pressure && asksForSecrets) {
            analysis.add("COMBO", "Pressure + request for secrets",
                    "Urgency or threats combined with a request for private information - the classic phishing pattern", 10, 0);
        }
        if (analysis.has("PRIZE", "FRAUD_OFFER", "INVESTMENT") && analysis.has("PAYMENT", "BANK_DETAILS")) {
            analysis.add("COMBO", "Offer that asks for money first",
                    "A prize, offer or investment that first asks for money or bank details (advance-fee scam)", 10, 0);
        }
        if (analysis.has("URL") && analysis.has("CREDENTIALS", "FAKE_LOGIN")) {
            analysis.add("COMBO", "Suspicious link + login request",
                    "A suspicious link is combined with a request to log in or verify the account", 8, 0);
        }
        if (analysis.has("AUTHORITY", "IMPERSONATION") && analysis.has("REMOTE_ACCESS", "PAYMENT", "OTP")) {
            analysis.add("COMBO", "Impersonation + payment/access request",
                    "Someone posing as an official asks for money, codes or remote access", 10, 0);
        }
        if (categoryCount >= 4) {
            analysis.add("COMBO", "Many warning signs together",
                    categoryCount + " different kinds of indicators were found in the same message", 8, 0);
        }
    }

    /** Final step: total the points, apply the safety caps and build the Result. */
    private static Result buildResult(String modality, Analysis analysis, String context) {
        int total = analysis.totalPoints();

        if (analysis.signalCount == 1 && total > 20) {
            total = 20;
            analysis.notes.add("Only one indicator was found. A single keyword is not enough evidence, so the score is limited to 20.");
        } else if (analysis.categories.size() == 1 && total > 45) {
            total = 45;
            analysis.notes.add("All warning signs belong to one category, so the score is limited to 45 (SUSPICIOUS) until other kinds of evidence appear.");
        }
        if (total > 100) {
            analysis.notes.add("The raw total was " + total + " points; the score is capped at 100.");
        }
        int score = Math.max(0, Math.min(100, total));

        if (analysis.indicators.isEmpty()) {
            analysis.notes.add("No phishing indicators were detected by the rule engine.");
        }

        List<Indicator> sorted = new ArrayList<>(analysis.indicators);
        sorted.sort(Comparator.comparingInt((Indicator i) -> i.points).reversed());

        List<String> recommendations = buildRecommendations(modality, analysis, score);
        String summary = context + " - " + topTitles(sorted, 3);
        return new Result(modality, score, sorted, analysis.urls, recommendations, analysis.notes, summary);
    }

    /** Chooses safety tips that match what was found. */
    private static List<String> buildRecommendations(String modality, Analysis analysis, int score) {
        Set<String> tips = new LinkedHashSet<>();
        if (score < 30) {
            tips.add("No strong phishing signs found. Stay alert and verify any unexpected request.");
        }
        if (analysis.has("URL")) {
            tips.add("Do not click suspicious links. Type the official website address yourself.");
        }
        if (analysis.has("OTP")) {
            tips.add("Never share your OTP or verification code with anyone - not even bank staff.");
        }
        if (analysis.has("CREDENTIALS", "FAKE_LOGIN")) {
            tips.add("Do not enter your username, password or banking credentials on pages opened from this message.");
        }
        if (analysis.has("BANK_DETAILS", "PIN")) {
            tips.add("Never share card numbers, CVV, PIN or bank account details.");
        }
        if (analysis.has("PAYMENT")) {
            tips.add("Do not send money, gift cards or crypto to unverified requests.");
        }
        if (analysis.has("SUSPENSION", "THREATS")) {
            tips.add("Threats of suspension, arrest or fines are pressure tactics. Stay calm and verify first.");
        }
        if (analysis.has("PRIZE", "FRAUD_OFFER")) {
            tips.add("Ignore prizes or offers you never applied for, especially if they ask for a fee.");
        }
        if (analysis.has("REMOTE_ACCESS")) {
            tips.add("Never install AnyDesk, TeamViewer or similar apps because a caller asked you to.");
        }
        if (analysis.has("INVESTMENT")) {
            tips.add("Guaranteed or very high returns are a classic fraud sign. Check the company with your financial regulator.");
        }
        if (analysis.has("SENDER", "IMPERSONATION", "AUTHORITY")) {
            tips.add("Verify the sender independently using contact details from the official website.");
        }
        if (score >= 30) {
            tips.add(modality.equals(VOICE)
                    ? "Hang up and call the organisation back on its official phone number."
                    : "Contact the official organisation directly if you are unsure.");
        }
        if (score >= 60) {
            String noun = modality.equals(VOICE) ? "call" : modality.equals(IMAGE) ? "message" : "email";
            tips.add("Report this " + noun + " to your IT/security team or your national cybercrime portal.");
        }
        return new ArrayList<>(tips);
    }

    // =====================================================================
    // 6. SMALL HELPER METHODS
    // =====================================================================

    private static void flag(UrlFinding finding, Map<String, String> issueExamples, String title, String description) {
        finding.issues.add(description);
        issueExamples.putIfAbsent(title, finding.url);
    }

    /** Finds all links in the text (without duplicates). */
    private static List<String> extractUrls(String text) {
        Set<String> urls = new LinkedHashSet<>();
        Set<String> seen = new HashSet<>();
        Matcher matcher = URL_PATTERN.matcher(safe(text));
        while (matcher.find()) {
            String url = matcher.group();
            while (!url.isEmpty() && ".,;:!?)".indexOf(url.charAt(url.length() - 1)) >= 0) {
                url = url.substring(0, url.length() - 1); // remove punctuation at the end of a sentence
            }
            if (url.length() > 3 && seen.add(url.toLowerCase(Locale.ROOT))) {
                urls.add(url);
            }
        }
        return new ArrayList<>(urls);
    }

    /** "https://user@www.example.com:8080/path" -> "example.com" */
    private static String extractHost(String url) {
        String host = url.toLowerCase(Locale.ROOT);
        int scheme = host.indexOf("://");
        if (scheme >= 0) {
            host = host.substring(scheme + 3);
        }
        host = host.split("[/?#]", 2)[0];
        int at = host.lastIndexOf('@');
        if (at >= 0) {
            host = host.substring(at + 1);
        }
        int colon = host.indexOf(':');
        if (colon >= 0) {
            host = host.substring(0, colon);
        }
        if (host.startsWith("www.")) {
            host = host.substring(4);
        }
        return host;
    }

    /**
     * Returns the brand a domain is pretending to be, or null if it looks fine.
     * Example: "paypa1-support.xyz" -> "paypal" (the 1 is used instead of an l).
     */
    private static String findImpersonatedBrand(String domain) {
        String readable = domain.replace('0', 'o').replace('1', 'l').replace('3', 'e')
                .replace('4', 'a').replace('5', 's');
        String[] parts = readable.split("[.\\-]");
        for (String brand : BRAND_DOMAINS.keySet()) {
            boolean mentionsBrand = false;
            for (String part : parts) {
                // Long brand names may appear inside a word ("securepaypal"); short ones must start it.
                if (brand.length() >= 6 ? part.contains(brand) : part.startsWith(brand)) {
                    mentionsBrand = true;
                    break;
                }
            }
            if (mentionsBrand && !isOfficialDomain(domain, brand)) {
                return brand;
            }
        }
        return null;
    }

    private static boolean isOfficialDomain(String domain, String brand) {
        String[] official = BRAND_DOMAINS.get(brand);
        if (official == null) {
            return false;
        }
        for (String good : official) {
            if (domain.equals(good) || domain.endsWith("." + good)) {
                return true;
            }
        }
        return false;
    }

    /** Returns the first well-known brand named in the text, or null. */
    private static String findMentionedBrand(String text) {
        String clean = normalize(text);
        for (String brand : BRAND_DOMAINS.keySet()) {
            if (Pattern.compile("(?<![a-z0-9])" + brand + "(?![a-z0-9])").matcher(clean).find()) {
                return brand;
            }
        }
        return null;
    }

    private static String topTitles(List<Indicator> indicators, int max) {
        List<String> titles = new ArrayList<>();
        for (Indicator indicator : indicators) {
            if (indicator.points > 0 && !titles.contains(indicator.title) && titles.size() < max) {
                titles.add(indicator.title);
            }
        }
        return titles.isEmpty() ? "no phishing indicators found" : String.join(", ", titles);
    }

    /** Lower case, straight apostrophes, single spaces - makes keyword matching reliable. */
    private static String normalize(String text) {
        return safe(text).replace('’', '\'').replace('‘', '\'')
                .replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }

    private static String quoteList(List<String> items, int max) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < items.size() && i < max; i++) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append('"').append(items.get(i)).append('"');
        }
        if (items.size() > max) {
            builder.append(" and ").append(items.size() - max).append(" more");
        }
        return builder.toString();
    }

    private static boolean containsAny(String text, String... words) {
        for (String word : words) {
            if (text.contains(word)) {
                return true;
            }
        }
        return false;
    }

    private static int countChar(String text, char wanted) {
        int count = 0;
        for (char c : text.toCharArray()) {
            if (c == wanted) {
                count++;
            }
        }
        return count;
    }

    private static int countDigits(String text) {
        int count = 0;
        for (char c : text.toCharArray()) {
            if (Character.isDigit(c)) {
                count++;
            }
        }
        return count;
    }

    /** Brand key -> how the brand is normally written ("paypal" -> "PayPal"). */
    private static String capitalize(String word) {
        switch (word) {
            case "paypal":
                return "PayPal";
            case "linkedin":
                return "LinkedIn";
            case "whatsapp":
                return "WhatsApp";
            case "fedex":
                return "FedEx";
            case "hdfc":
            case "icici":
            case "sbi":
            case "dhl":
                return word.toUpperCase(Locale.ROOT);
            default:
                return word.isEmpty() ? word : Character.toUpperCase(word.charAt(0)) + word.substring(1);
        }
    }

    private static String shorten(String text, int max) {
        return text.length() <= max ? text : text.substring(0, max - 3) + "...";
    }

    private static String safe(String text) {
        return text == null ? "" : text;
    }
}
