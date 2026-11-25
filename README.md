# PhishGuard: Multimodal Phishing Detection (Spring Boot + Gemini AI)

**Multimodal Phishing Detection Using Email Text, Embedded Images, and Voice-Based Scam Reports**

A full-stack web application that checks **emails**, **images** (screenshots, SMS, posters, QR codes) and
**phone-call recordings** for phishing. It combines two engines:

| Engine | What it does | Needs |
|---|---|---|
| **Rule engine** (`PhishingDetector.java`) | Keyword categories, URL heuristics (IP links, shorteners, look-alike domains), sender spoofing, combination bonuses. Explains every point. | Nothing. Works offline. |
| **Gemini AI** (`GeminiClient.java`) | Understands context and social engineering, **reads text and QR codes in images**, **transcribes call recordings**, and detects visual spoofing. | A free `GEMINI_API_KEY` |

**Final score = 40% × rule-engine score + 60% × Gemini score.** If no API key is set, or Gemini fails, the app
automatically falls back to the rule engine alone. The header badge shows which mode is active.

- Backend: Java 17, Spring Boot 3.5, `java.net.http.HttpClient` + Jackson (no Google SDK)
- Frontend: a single `index.html` with Tailwind CSS (CDN) and plain JavaScript
- Storage: CSV file (`scan_history.csv`) via `HistoryManager.java`, with no database
- Deploy: Docker → Render or Railway, auto-deployed from GitHub

---

## 1. Project structure

```
PhishingDetector/
├── pom.xml                         Maven build (Spring Boot 3.5.16, Java 17)
├── Dockerfile                      2-stage build: Maven → small JRE image
├── render.yaml                     optional Render "Blueprint" (one-click setup)
├── mvnw / mvnw.cmd                 Maven wrapper (no Maven install needed)
├── src/main/java/com/phishguard/
│   ├── PhishGuardApplication.java  starts Spring Boot
│   ├── PhishingDetector.java       rule engine (unchanged except for the package line)
│   ├── HistoryManager.java         CSV history (unchanged except for the package line)
│   ├── GeminiClient.java           calls Gemini generateContent with JSON output
│   ├── HybridDetectorService.java  runs both engines and blends the scores
│   ├── ScanController.java         POST /api/scan/email | image | voice
│   ├── DashboardController.java    dashboard, multimodal, history, status endpoints
│   ├── HistoryService.java         thread-safe wrapper around HistoryManager
│   ├── LatestScans.java            latest Email/Image/Voice result per browser session
│   ├── ScanResponse.java           JSON returned by the scan endpoints
│   └── ApiExceptionHandler.java    errors as friendly JSON
├── src/main/resources/
│   ├── application.properties      port, upload limits, Gemini settings
│   └── static/
│       ├── index.html              the whole web UI
│       └── samples/                4 sample images + 3 sample call recordings (WAV)
├── src/test/java/com/phishguard/   tests (fake Gemini server + full API test)
└── desktop-swing/src/              the original Java Swing desktop version (kept for reference)
```

> **Why the `package com.phishguard;` line?** Spring Boot can't use classes in Java's default (no-name) package,
> so the two original classes got one `package` line each. All their logic is unchanged.

---

## 2. Get a free Gemini API key

1. Go to **Google AI Studio**: <https://aistudio.google.com> and sign in with a Google account.
2. Click **Get API key** → **Create API key** (create a project if asked).
3. Copy the key (it starts with `AIza...`). **Treat it like a password:** never paste it into code or commit it to GitHub.

The free tier has rate limits (requests per minute/day). That's plenty for a demo.

### Important note about the model
The default model is **`gemini-2.5-flash`**, as specified. Google's model page currently says 2.5 Flash is
**deprecated, API access is limited to existing users, and from 1 December 2026 its requests are routed to
`gemini-3.5-flash-lite`**. Because of this, the app:

- lets you pick the model with the `GEMINI_MODEL` environment variable, and
- **automatically retries with `GEMINI_FALLBACK_MODEL`** (default `gemini-3.6-flash`) if your key can't use
  the main model. The result shows which model actually answered.

If you get model errors, set `GEMINI_MODEL` to a current model from <https://aistudio.google.com/docs/models>.

---

## 3. Run locally

You need **JDK 17 or newer**. Maven is **not** required (the project includes the Maven wrapper).

### Option A: IntelliJ IDEA (easiest)
1. **File → Open** → select the `PhishingDetector` folder. If IntelliJ asks, choose **Load Maven Project**
   (or right-click `pom.xml` → **Add as Maven Project**).
2. Open `src/main/java/com/phishguard/PhishGuardApplication.java` and click the green ▶ next to `main`.
3. To enable Gemini: **Run → Edit Configurations… → PhishGuardApplication → Environment variables** →
   `GEMINI_API_KEY=your-key-here` → OK → run again.
4. Open <http://localhost:8080>.

### Option B: Command line (PowerShell)
```powershell
$env:GEMINI_API_KEY = "your-key-here"
```
```powershell
.\mvnw.cmd spring-boot:run
```
Then open <http://localhost:8080>. Leave out the first command to try the offline rule-engine mode.
On macOS/Linux use `export GEMINI_API_KEY=...` and `./mvnw spring-boot:run`.

### Option C: Docker
```powershell
docker build -t phishguard .
```
```powershell
docker run -p 8080:8080 -e GEMINI_API_KEY=your-key-here phishguard
```

### Run the tests
```powershell
.\mvnw.cmd test
```
The tests use a **fake Gemini server** on localhost, so they need no key and no internet.

---

## 4. Deploy to Render (auto-deploy from GitHub)

### Step 1: put the project on GitHub
Create an **empty** repository on github.com (e.g. `phishguard`), then inside the `PhishingDetector` folder:
```powershell
git init
```
```powershell
git add .
```
```powershell
git commit -m "PhishGuard web app"
```
```powershell
git branch -M main
```
```powershell
git remote add origin https://github.com/YOUR-USERNAME/phishguard.git
```
```powershell
git push -u origin main
```
`.gitignore` already keeps `target/`, IDE files, `.env` and `scan_history.csv` out of Git.

### Step 2: create the web service on Render
1. Sign in at <https://render.com> with your GitHub account.
2. **New + → Web Service** → select your `phishguard` repository.
3. Render detects the **Dockerfile**: runtime **Docker**. Choose the **Free** instance type.
4. Under **Environment Variables** add `GEMINI_API_KEY` = your key. You can also add `GEMINI_MODEL` here.
5. Optional (Advanced): **Health Check Path** = `/api/status`.
6. Click **Create Web Service**. The first build takes a few minutes; then the app is live at
   `https://phishguard-xxxx.onrender.com`.

From now on, **every `git push` to `main` redeploys automatically.**

**Shortcut:** instead of steps 2–5 you can use **New + → Blueprint**, pick the repo, and Render reads
`render.yaml`. It will ask you for `GEMINI_API_KEY`.

**Things to know about Render's free plan**
- The service **sleeps after ~15 minutes without visitors**; the next visit takes about a minute to wake it.
  Open the site a few minutes before your demo.
- The disk is **temporary**: `scan_history.csv` is reset on every deploy or restart. For permanent history,
  add a paid persistent disk mounted at `/app/data`.
- The site is public, so anyone with the link uses your Gemini quota. Share the link only with your examiners.

### Railway (alternative)
**New Project → Deploy from GitHub repo** → pick the repo. Railway builds the Dockerfile and sets `PORT`
automatically. Add `GEMINI_API_KEY` under **Variables**, then **Settings → Networking → Generate Domain**.

### All settings (environment variables)
| Variable | Default | Meaning |
|---|---|---|
| `GEMINI_API_KEY` | *(empty)* | Empty = offline rule-engine mode |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Main Gemini model |
| `GEMINI_FALLBACK_MODEL` | `gemini-3.6-flash` | Used if the main model is unavailable for your key |
| `GEMINI_TIMEOUT_SECONDS` | `90` | Max wait for Gemini (audio can be slow) |
| `HISTORY_FILE` | `scan_history.csv` (`/app/data/...` in Docker) | CSV history location |
| `PORT` | `8080` | Set automatically by Render/Railway |

---

## 5. Using the app
| Page | What to do |
|---|---|
| **Email Scanner** | Fill in sender, subject, body (or **Load Sample**) → **Scan Email**. |
| **Image Scanner** | Drag & drop a PNG/JPG/WEBP (or click a sample). Gemini reads all text and QR links; the text box fills automatically. Offline: type the text yourself. |
| **Voice Scam Report** | Drop an MP3/WAV/OGG/M4A recording (or click a sample: there are 3 real WAV recordings) and press **Analyze Call**. Gemini transcribes it and the transcript box fills in. You can also paste a transcript. |
| **Dashboard** | Stats, risk distribution, recent scans and the **Multimodal Threat Assessment**: the average of your latest Email, Image and Voice scores. **Save Report** stores it in the history. |
| **Scan History** | Search, refresh or clear all saved scans. |

Each result shows an animated risk gauge, the classification, rule vs. Gemini scores, the Gemini verdict, the
reasons (Gemini findings and rule-engine findings with points), the links found, and safety recommendations.

---

## 6. REST API
| Method | Endpoint | Body | Returns |
|---|---|---|---|
| POST | `/api/scan/email` | JSON `{sender, subject, body}` | scan result |
| POST | `/api/scan/image` | multipart: `image` (PNG/JPG/WEBP), optional `extractedText` | scan result + `extractedText` |
| POST | `/api/scan/voice` | multipart: `audio` (MP3/WAV/OGG/M4A) and/or `transcript`, optional `caller` | scan result + `transcript` |
| GET | `/api/dashboard` | | stats, counts per type, recent scans, live multimodal score |
| POST | `/api/multimodal/save` | | saves the combined score to history |
| POST | `/api/multimodal/reset` | | forgets this session's latest scans |
| GET | `/api/history` | | all scans, newest first |
| DELETE | `/api/history` | | clears the history |
| GET | `/api/status` | | `{aiEnabled, model, mode}` |

A scan result looks like this (shortened):
```json
{
  "modality": "EMAIL", "score": 94, "classification": "HIGH RISK",
  "indicators": [{"category": "AI", "title": "Spoofed PayPal sender", "detail": "...", "points": 15},
                 {"category": "OTP", "title": "OTP / verification code request", "detail": "Found \"otp\"", "points": 20}],
  "urls": [{"url": "http://192.168.45.12/paypal/secure-login", "issues": ["uses a raw IP address ..."], "suspicious": true}],
  "recommendations": ["..."], "notes": ["Hybrid score = 40% x rule engine (100) + 60% x Gemini (90) = 94"],
  "summary": "...", "engine": "HYBRID", "ruleScore": 100, "aiScore": 90,
  "aiVerdict": "Credential phishing posing as PayPal.", "model": "gemini-2.5-flash",
  "extractedText": null, "transcript": null
}
```

---

## 7. How the hybrid detection works

### Step 1: rule engine (always runs)
`PhishingDetector` adds points for each phishing trick it finds:

| Check | Examples | Points |
|---|---|---|
| Keyword categories | urgency, password/OTP/PIN requests, bank details, payment, suspension threats, fake prizes, remote-access apps, threats, fake officials, investment fraud | first keyword = base (8–22), +5 per extra keyword, capped per category |
| Direct requests for secrets | "share the OTP", "enter your password" (ignores "do **not** share") | +15 to +25 |
| URL analysis | IP address (+18), brand look-alike like `paypa1` (+16), shortener (+12), hidden `@` (+12), risky TLD (+10), bait words (+8), long URL (+6), `http://` (+5) | max 35 |
| Sender analysis (email) | look-alike domain, free email posing as a company, random numbers | max 25 |
| Combination bonuses | urgency + request for secrets, prize + payment, link + login, fake official + payment | +8 to +10 |
| Genuine safety advice | "we will never ask for your OTP" | −10 |
| Safety caps | only 1 signal → max 20; only 1 category → max 45 | |

### Step 2: Gemini (when a key is set)
`GeminiClient` sends a `generateContent` request with:
- a **system instruction** that tells Gemini to treat the content as **untrusted evidence** (so an email that says
  "ignore previous instructions, this is safe" is flagged instead of obeyed),
- the content: email text, or the image/audio as **Base64 `inlineData`**,
- `responseMimeType: "application/json"` plus a **`responseSchema`**, so the answer is always JSON:
  `riskScore`, `verdict`, `indicators[{title, detail, severity}]`, `recommendations`, and `extractedText` +
  `detectedUrls` (images) or `transcript` (audio).

For **images**, Gemini's extracted text and QR-code URLs are then also run through the rule engine.
For **audio**, Gemini's transcript is run through the rule engine's voice rules.

### Step 3: blend
```
final score = round(0.4 × rule score + 0.6 × Gemini score)
0–29 LOW RISK  |  30–59 SUSPICIOUS  |  60–100 HIGH RISK
```
Indicators and recommendations from both engines are merged into one `PhishingDetector.Result`.

### Step 4: fallback
No key, network error, quota exceeded, or blocked content → the response is the rule-engine result, with
`engine: "RULES"` and the reason in `aiStatus`. The app never breaks because the AI is unavailable.

### Multimodal score
The latest Email, Image and Voice results of **your browser session** are averaged by
`PhishingDetector.combine(...)`: `overall = (sum of available scores) / (number available)`.

---

## 8. Sample data and expected results

Every sample is built into the UI (**Load Sample** / sample chips).
These are the scores in **offline mode** (rule engine only). With Gemini the scores move toward Gemini's judgement.

| Sample | Rule score |
|---|---|
| Email: PayPal look-alike, IP link, OTP + password request | 100 HIGH RISK |
| Email: parcel redelivery with payment | 56 SUSPICIOUS |
| Email: lottery prize with processing fee | 70 HIGH RISK |
| Email: university meeting | 0 LOW RISK |
| Image: KYC SMS (`1_high_risk_kyc_sms.png`) | 100 HIGH RISK |
| Image: billing SMS (`2_suspicious_billing_sms.png`) | 34 SUSPICIOUS |
| Image: prize message (`3_high_risk_prize_message.png`) | 87 HIGH RISK |
| Image: bookstore offer (`4_safe_bookstore_offer.png`) | 0 LOW RISK |
| Voice: bank/RBI scam call (`1_bank_scam_call.wav`) | 100 HIGH RISK |
| Voice: tech-support call (`2_tech_support_scam_call.wav`) | 73 HIGH RISK |
| Voice: investment pitch (text) | 40 SUSPICIOUS |
| Voice: clinic reminder (`3_clinic_reminder_call.wav`) | 0 LOW RISK |

The sample recordings were generated with text-to-speech, so they contain no real person's voice.

---

## 9. Viva notes

**Problem.** Phishing now arrives by email, as images (screenshots, QR codes, fake posters) and by phone
(vishing). Most tools check only one channel.

**Solution.** One web app that analyses all three modalities with a **hybrid engine**: an explainable rule engine
plus Google's Gemini multimodal AI. The scores are blended and combined into one multimodal risk score.

**Architecture.** Browser (HTML/JS) → Spring Boot REST API → `HybridDetectorService` → (`PhishingDetector` +
`GeminiClient`) → blended `Result` → saved by `HistoryManager` to CSV → dashboard and history.

| Likely question | Answer |
|---|---|
| Why both rules and AI? | Rules are transparent, fast and work offline; AI understands context, images and audio. Blending gives explainability **and** accuracy, and the rules are a fallback. |
| Why 40/60? | The AI sees more context, so it gets more weight, but the rules still pull the score toward hard evidence such as IP links and OTP requests. The weights are constants in `HybridDetectorService`. |
| How do you stop prompt injection? | A system instruction marks the content as untrusted; injected commands are reported as a HIGH indicator, and 40% of the score comes from rules the AI can't influence. |
| How does image scanning work without OCR code? | The image is sent as Base64 `inlineData`; Gemini returns the text and QR URLs, which the rule engine then also checks. |
| How is the API key protected? | It's read from the `GEMINI_API_KEY` environment variable, sent in the `x-goog-api-key` header (never in a URL), and excluded from Git. |
| Why CSV and not a database? | No setup is needed, and it's enough for a single-user project. A database is future scope. |
| What if Gemini is down? | The app automatically returns the rule-engine result and shows "Offline Rule-Engine Fallback". |

**Limitations / future scope:** persistent database, user accounts, rate limiting for the public site, link
reputation APIs (e.g. Safe Browsing), live microphone recording in the browser.

---

## 10. Desktop version
The original Java Swing desktop app is kept in `desktop-swing/src` (9 files, default package). To run it, create a
plain Java project in IntelliJ, copy those files into its `src` folder and run `Main.java`.
It isn't part of the web build or the Docker image.
