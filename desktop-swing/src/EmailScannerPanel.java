import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

/**
 * EmailScannerPanel - the user enters the sender, subject and body of an email.
 * PhishingDetector.analyzeEmail() scores it and the ResultPanel on the right shows why.
 */
public class EmailScannerPanel extends JPanel {

    private final Main app;
    private final Main.HintTextField senderField = new Main.HintTextField("e.g. security-alert@paypa1-support.xyz", "email");
    private final Main.HintTextField subjectField = new Main.HintTextField("e.g. Urgent: your account has been suspended", "file");
    private final JTextArea contentArea = Main.createTextArea(
            "Paste the full email text here...\n\nTip: press Ctrl+Enter to scan.");
    private final ResultPanel resultPanel = new ResultPanel();
    private int sampleIndex = 0;

    /** Test emails: {sender, subject, body}. "Load Sample" cycles through them. */
    private static final String[][] SAMPLES = {
            {
                    "security-alert@paypa1-support.xyz",
                    "URGENT: Your account has been suspended!!!",
                    "Dear Customer,\n\n"
                            + "We detected unusual activity on your PayPal account and it has been temporarily suspended. "
                            + "To restore access you must verify your account within 24 hours, otherwise it will be permanently closed.\n\n"
                            + "Click here to verify now: http://192.168.45.12/paypal/secure-login\n"
                            + "Backup link: bit.ly/pp-verify-acc\n\n"
                            + "Please enter your password and the OTP sent to your phone to confirm your identity.\n\n"
                            + "PayPal Security Team"
            },
            {
                    "delivery-notice@parcel-track-info.com",
                    "Delivery attempt failed",
                    "Hello,\n\n"
                            + "We were unable to deliver your parcel today because the address was incomplete. "
                            + "Please update your details within 48 hours using the link below, otherwise the parcel "
                            + "will be returned to the sender:\n"
                            + "https://parcel-track-info.com/redelivery\n\n"
                            + "A small redelivery payment of $1.99 applies.\n\n"
                            + "Thank you,\nDelivery Team"
            },
            {
                    "rewards.team2291@gmail.com",
                    "Congratulations! You have been selected",
                    "Hello,\n\n"
                            + "Congratulations! Your email address was selected as the winner of our monthly lucky draw. "
                            + "You have won a cash prize of $5,000.\n\n"
                            + "To claim your reward, reply with your full name and address. "
                            + "A small processing fee of $25 is required to release the prize.\n\n"
                            + "Regards,\nRewards Department"
            },
            {
                    "priya.sharma@university.edu",
                    "Project meeting moved to Friday",
                    "Hi team,\n\n"
                            + "The project review meeting has been moved to Friday at 3 PM in Room 204. "
                            + "Please bring your progress slides and the updated test results.\n\n"
                            + "The agenda is on the class portal: https://portal.university.edu/courses/cs-project\n\n"
                            + "Thanks,\nPriya"
            }
    };

    public EmailScannerPanel(Main app) {
        this.app = app;
        Main.setupPage(this,
                Main.createPageHeader("Email Scanner",
                        "Check an email for urgent language, fake links, sender spoofing and requests for secrets.", "email"),
                Main.createTwoColumnBody(createInputCard(), Main.createResultCard(resultPanel)));
        Main.bindCtrlEnter(contentArea, this::scan);
        Main.bindCtrlEnter(senderField, this::scan);
        Main.bindCtrlEnter(subjectField, this::scan);
    }

    private JComponent createInputCard() {
        Main.RoundedPanel card = new Main.RoundedPanel(new GridBagLayout());
        card.setBorder(new EmptyBorder(22, 22, 22, 22));

        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0;
        gc.weightx = 1;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.anchor = GridBagConstraints.NORTHWEST;

        gc.gridy = 0;
        gc.insets = new Insets(0, 0, 20, 0);
        card.add(Main.createCardTitle("Email Details", "email"), gc);

        gc.gridy = 1;
        gc.insets = new Insets(0, 0, 0, 0);
        card.add(Main.createFieldLabel("Sender email"), gc);
        gc.gridy = 2;
        gc.insets = new Insets(0, 0, 16, 0);
        card.add(senderField, gc);

        gc.gridy = 3;
        gc.insets = new Insets(0, 0, 0, 0);
        card.add(Main.createFieldLabel("Email subject"), gc);
        gc.gridy = 4;
        gc.insets = new Insets(0, 0, 16, 0);
        card.add(subjectField, gc);

        gc.gridy = 5;
        gc.insets = new Insets(0, 0, 0, 0);
        card.add(Main.createFieldLabel("Email content"), gc);
        gc.gridy = 6;
        gc.weighty = 1;
        gc.fill = GridBagConstraints.BOTH;
        gc.insets = new Insets(0, 0, 18, 0);
        card.add(Main.wrapTextArea(contentArea), gc);

        Main.ModernButton scanButton = new Main.ModernButton("Scan Email", "scan", Main.ModernButton.Style.PRIMARY);
        Main.ModernButton clearButton = new Main.ModernButton("Clear", "clear", Main.ModernButton.Style.SECONDARY);
        Main.ModernButton sampleButton = new Main.ModernButton("Load Sample", "file", Main.ModernButton.Style.GHOST);
        scanButton.addActionListener(e -> scan());
        clearButton.addActionListener(e -> clear());
        sampleButton.addActionListener(e -> loadSample());
        sampleButton.setToolTipText("Fills the form with a test email (" + SAMPLES.length + " samples)");

        gc.gridy = 7;
        gc.weighty = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.insets = new Insets(0, 0, 0, 0);
        card.add(Main.createButtonRow(scanButton, clearButton, sampleButton), gc);
        return card;
    }

    /** Reads the form, runs the detector and shows + saves the result. */
    private void scan() {
        String sender = senderField.getText().trim();
        String subject = subjectField.getText().trim();
        String body = contentArea.getText().trim();
        if (subject.isEmpty() && body.isEmpty()) {
            Main.showWarning(this, "Please enter the email subject or content before scanning.");
            return;
        }
        PhishingDetector.Result result = PhishingDetector.analyzeEmail(sender, subject, body);
        resultPanel.showResult(result);
        app.onScanCompleted(result);
    }

    private void clear() {
        senderField.setText("");
        subjectField.setText("");
        contentArea.setText("");
        resultPanel.clear();
        senderField.requestFocusInWindow();
    }

    private void loadSample() {
        String[] sample = SAMPLES[sampleIndex];
        sampleIndex = (sampleIndex + 1) % SAMPLES.length;
        senderField.setText(sample[0]);
        subjectField.setText(sample[1]);
        contentArea.setText(sample[2]);
        contentArea.setCaretPosition(0);
        resultPanel.clear();
    }
}
