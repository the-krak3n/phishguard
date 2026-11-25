import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;

/**
 * VoiceScannerPanel - the user pastes the transcript of a suspicious phone call.
 *
 * Real microphone recording and speech recognition are intentionally NOT included.
 * The transcript is analysed by PhishingDetector.analyzeVoiceTranscript() for OTP / PIN / bank
 * requests, remote access apps, threats, fake officials, urgency and investment fraud.
 */
public class VoiceScannerPanel extends JPanel {

    private final Main app;
    private final Main.HintTextField callerField = new Main.HintTextField("e.g. +91 98XXX XXX21 or \"Bank customer care\"", "voice");
    private final JTextArea transcriptArea = Main.createTextArea(
            "Paste or type what the caller said...\n\nTip: press Ctrl+Enter to analyse.");
    private final ResultPanel resultPanel = new ResultPanel();
    private int sampleIndex = 0;

    /** Test transcripts: {caller, transcript}. */
    private static final String[][] SAMPLES = {
            {"+91 98XXX XXX21",
                    "Hello sir, I am calling from the RBI head office, bank security department. Your debit card has been "
                            + "blocked due to suspicious activity. To unblock it immediately, please tell me the 16 digit card "
                            + "number and CVV. You will receive an OTP now, please share the OTP with me. If you do not cooperate, "
                            + "a legal case will be filed and police will come to arrest you today."},
            {"Unknown international number",
                    "Hi, this is Mike from Microsoft technical support. We have detected a virus on your computer. "
                            + "Please download the AnyDesk app so I can get remote access and fix it. There is a one-time "
                            + "service charge of $199 that you can pay with a gift card."},
            {"Investment advisor",
                    "Hello madam, we have a special investment opportunity in crypto trading. You will get guaranteed "
                            + "returns of 30 percent every month. Many people have doubled their money. This is a limited "
                            + "time offer, so just invest a small amount today."},
            {"City Clinic",
                    "Hi, this is Dr. Mehta's clinic calling to remind you about your appointment tomorrow at 10:30 AM. "
                            + "If you need to reschedule, please call the clinic reception. Thank you."}
    };

    public VoiceScannerPanel(Main app) {
        this.app = app;
        Main.setupPage(this,
                Main.createPageHeader("Voice Scam Report",
                        "Analyse a phone-call transcript for OTP requests, fake officials, threats and remote-access scams.", "voice"),
                Main.createTwoColumnBody(createInputCard(), Main.createResultCard(resultPanel)));
        Main.bindCtrlEnter(transcriptArea, this::analyze);
    }

    private JComponent createInputCard() {
        Main.RoundedPanel card = new Main.RoundedPanel(new GridBagLayout());
        card.setBorder(new EmptyBorder(22, 22, 22, 22));

        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;

        gc.gridy = 0;
        gc.insets = new Insets(0, 0, 18, 0);
        card.add(Main.createCardTitle("Call Transcript", "voice"), gc);

        gc.gridy = 1;
        gc.insets = new Insets(0, 0, 18, 0);
        card.add(createInfoBanner(), gc);

        gc.gridy = 2;
        gc.insets = new Insets(0, 0, 0, 0);
        card.add(Main.createFieldLabel("Caller (optional)"), gc);
        gc.gridy = 3;
        gc.insets = new Insets(0, 0, 16, 0);
        card.add(callerField, gc);

        gc.gridy = 4;
        gc.insets = new Insets(0, 0, 0, 0);
        card.add(Main.createFieldLabel("Call transcript"), gc);
        gc.gridy = 5;
        gc.weighty = 1;
        gc.fill = GridBagConstraints.BOTH;
        gc.insets = new Insets(0, 0, 18, 0);
        card.add(Main.wrapTextArea(transcriptArea), gc);

        Main.ModernButton analyzeButton = new Main.ModernButton("Analyze Transcript", "scan", Main.ModernButton.Style.PRIMARY);
        Main.ModernButton clearButton = new Main.ModernButton("Clear", "clear", Main.ModernButton.Style.SECONDARY);
        Main.ModernButton sampleButton = new Main.ModernButton("Load Sample", "file", Main.ModernButton.Style.GHOST);
        analyzeButton.addActionListener(e -> analyze());
        clearButton.addActionListener(e -> clear());
        sampleButton.addActionListener(e -> loadSample());
        sampleButton.setToolTipText("Fills in a test call transcript (" + SAMPLES.length + " samples)");

        gc.gridy = 6;
        gc.weighty = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.insets = new Insets(0, 0, 0, 0);
        card.add(Main.createButtonRow(analyzeButton, clearButton, sampleButton), gc);
        return card;
    }

    /** Small blue note explaining that speech recognition is not included. */
    private JComponent createInfoBanner() {
        Main.RoundedPanel banner = new Main.RoundedPanel(new BorderLayout(12, 0), 14,
                Main.withAlpha(Main.BLUE, 26), Main.withAlpha(Main.BLUE, 90));
        banner.setBorder(new EmptyBorder(12, 14, 12, 14));
        banner.add(new JLabel(Main.icon("info", 20, new Color(147, 197, 253))), BorderLayout.WEST);
        JPanel texts = new JPanel(new GridLayout(2, 1, 0, 2));
        texts.setOpaque(false);
        texts.add(Main.createLabel("No recording needed", Main.font(Font.BOLD, 13), Main.TEXT));
        texts.add(Main.createLabel("Paste a transcript or type what the caller said.",
                Main.font(Font.PLAIN, 12.5f), Main.TEXT_MUTED));
        banner.add(texts, BorderLayout.CENTER);
        return banner;
    }

    private void analyze() {
        String transcript = transcriptArea.getText().trim();
        if (transcript.isEmpty()) {
            Main.showWarning(this, "Please paste or type the call transcript before analysing.");
            return;
        }
        PhishingDetector.Result result = PhishingDetector.analyzeVoiceTranscript(transcript, callerField.getText().trim());
        resultPanel.showResult(result);
        app.onScanCompleted(result);
    }

    private void clear() {
        callerField.setText("");
        transcriptArea.setText("");
        resultPanel.clear();
        transcriptArea.requestFocusInWindow();
    }

    private void loadSample() {
        String[] sample = SAMPLES[sampleIndex];
        sampleIndex = (sampleIndex + 1) % SAMPLES.length;
        callerField.setText(sample[0]);
        transcriptArea.setText(sample[1]);
        transcriptArea.setCaretPosition(0);
        resultPanel.clear();
    }
}
