import javax.imageio.ImageIO;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FileDialog;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Frame;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.awt.Window;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * ImageScannerPanel - the user uploads a screenshot / poster (JPG, JPEG or PNG),
 * sees a preview, and types the text that is visible in the image.
 *
 * Automatic text recognition (OCR) is intentionally NOT included to keep the
 * project simple. The typed text is analysed by PhishingDetector.analyzeImageText().
 */
public class ImageScannerPanel extends JPanel {

    private final Main app;
    private final ImagePreview preview = new ImagePreview();
    private final JLabel fileLabel = Main.createLabel("No image selected  |  JPG, JPEG or PNG", Main.font(Font.PLAIN, 12.5f), Main.TEXT_MUTED);
    private final JTextArea extractedTextArea = Main.createTextArea(
            "Type the text you can see in the image...\n\nTip: press Ctrl+Enter to analyse.");
    private final ResultPanel resultPanel = new ResultPanel();
    private String imageName;
    private int sampleIndex = 0;

    /** Test cases: {sender shown in the generated screenshot, text in the image}. */
    private static final String[][] SAMPLES = {
            {"VK-BNKALRT", "ALERT: Your bank KYC has expired. Your account will be blocked today. "
                    + "Update KYC immediately at http://kyc-update-bank.top/login and enter your card number, "
                    + "CVV and OTP to avoid suspension."},
            {"Netflix Billing", "Your Netflix payment failed. Update your payment method to keep watching: "
                    + "https://netflix-billing-help.com"},
            {"Lucky Draw 2026", "Congratulations! You won a FREE iPhone 15 in our lucky draw. "
                    + "Pay only Rs. 99 delivery charge. Claim now: tinyurl.com/free-iphone-win"},
            {"City Book Store", "Flat 20% off on all books this weekend at City Book Store, MG Road. "
                    + "Offer valid till Sunday. See you there!"}
    };

    public ImageScannerPanel(Main app) {
        this.app = app;
        Main.setupPage(this,
                Main.createPageHeader("Image Scanner",
                        "Check screenshots, posters and SMS images for scam text, fake login requests and bad links.", "image"),
                Main.createTwoColumnBody(createInputCard(), Main.createResultCard(resultPanel)));
        Main.bindCtrlEnter(extractedTextArea, this::analyze);
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
        card.add(Main.createCardTitle("Image & Extracted Text", "image"), gc);

        // upload button + file name
        Main.ModernButton uploadButton = new Main.ModernButton("Upload Image", "upload", Main.ModernButton.Style.SECONDARY);
        uploadButton.addActionListener(e -> chooseImage());
        JPanel uploadRow = new JPanel(new BorderLayout(14, 0));
        uploadRow.setOpaque(false);
        uploadRow.add(uploadButton, BorderLayout.WEST);
        fileLabel.setPreferredSize(new Dimension(40, fileLabel.getPreferredSize().height));
        uploadRow.add(fileLabel, BorderLayout.CENTER);
        gc.gridy = 1;
        gc.insets = new Insets(0, 0, 14, 0);
        card.add(uploadRow, gc);

        gc.gridy = 2;
        gc.weighty = 0.55;
        gc.fill = GridBagConstraints.BOTH;
        gc.insets = new Insets(0, 0, 16, 0);
        card.add(preview, gc);

        gc.gridy = 3;
        gc.weighty = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.insets = new Insets(0, 0, 0, 0);
        card.add(Main.createFieldLabel("Text in the image (typed - no OCR)"), gc);

        gc.gridy = 4;
        gc.weighty = 0.45;
        gc.fill = GridBagConstraints.BOTH;
        gc.insets = new Insets(0, 0, 18, 0);
        JComponent textBox = Main.wrapTextArea(extractedTextArea);
        textBox.setPreferredSize(new Dimension(200, 100));
        card.add(textBox, gc);

        Main.ModernButton analyzeButton = new Main.ModernButton("Analyze Image", "scan", Main.ModernButton.Style.PRIMARY);
        Main.ModernButton clearButton = new Main.ModernButton("Clear", "clear", Main.ModernButton.Style.SECONDARY);
        Main.ModernButton sampleButton = new Main.ModernButton("Load Sample", "file", Main.ModernButton.Style.GHOST);
        analyzeButton.addActionListener(e -> analyze());
        clearButton.addActionListener(e -> clear());
        sampleButton.addActionListener(e -> loadSample());
        sampleButton.setToolTipText("Creates a sample screenshot with its text (" + SAMPLES.length + " samples)");

        gc.gridy = 5;
        gc.weighty = 0;
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.insets = new Insets(0, 0, 0, 0);
        card.add(Main.createButtonRow(analyzeButton, clearButton, sampleButton), gc);
        return card;
    }

    /** Opens the system file dialog and loads the chosen image. */
    private void chooseImage() {
        Window window = SwingUtilities.getWindowAncestor(this);
        FileDialog dialog = new FileDialog(window instanceof Frame ? (Frame) window : null, "Select an image (JPG, JPEG or PNG)", FileDialog.LOAD);
        dialog.setFile("*.jpg;*.jpeg;*.png");                    // filter on Windows
        dialog.setFilenameFilter((dir, name) -> isSupportedImage(name)); // filter on macOS / Linux
        dialog.setVisible(true);

        if (dialog.getFile() == null) {
            return; // the user pressed Cancel
        }
        File file = new File(dialog.getDirectory(), dialog.getFile());
        if (!isSupportedImage(file.getName())) {
            JOptionPane.showMessageDialog(this, "Please choose a JPG, JPEG or PNG image.", "Unsupported file", JOptionPane.WARNING_MESSAGE);
            return;
        }
        try {
            BufferedImage image = ImageIO.read(file);
            if (image == null) {
                throw new IOException("unknown image format");
            }
            imageName = file.getName();
            preview.setImage(image);
            long kb = Math.max(1, file.length() / 1024);
            fileLabel.setText(file.getName() + "  |  " + image.getWidth() + " x " + image.getHeight() + " px  |  " + kb + " KB");
            fileLabel.setForeground(Main.TEXT);
            resultPanel.clear();
            extractedTextArea.requestFocusInWindow();
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "This file could not be opened as an image:\n" + ex.getMessage(),
                    "Image error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static boolean isSupportedImage(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".png");
    }

    private void analyze() {
        String text = extractedTextArea.getText().trim();
        if (text.isEmpty()) {
            Main.showWarning(this, imageName == null
                    ? "Please upload an image and type the text you can see in it."
                    : "Please type the text you can see in the image.\n(Automatic OCR is not part of this project.)");
            return;
        }
        PhishingDetector.Result result = PhishingDetector.analyzeImageText(text, imageName);
        resultPanel.showResult(result);
        app.onScanCompleted(result);
    }

    private void clear() {
        imageName = null;
        preview.setImage(null);
        fileLabel.setText("No image selected  |  JPG, JPEG or PNG");
        fileLabel.setForeground(Main.TEXT_MUTED);
        extractedTextArea.setText("");
        resultPanel.clear();
    }

    private void loadSample() {
        String[] sample = SAMPLES[sampleIndex];
        sampleIndex = (sampleIndex + 1) % SAMPLES.length;
        BufferedImage image = createSampleScreenshot(sample[0], sample[1]);
        imageName = "sample-screenshot-" + sampleIndex + ".png";
        preview.setImage(image);
        fileLabel.setText(imageName + "  |  generated sample  |  " + image.getWidth() + " x " + image.getHeight() + " px");
        fileLabel.setForeground(Main.TEXT);
        extractedTextArea.setText(sample[1]);
        extractedTextArea.setCaretPosition(0);
        resultPanel.clear();
    }

    /**
     * Draws a simple phone-message screenshot so the sample has a real image to preview.
     * (Also used to create the PNG files in the samples folder.)
     */
    public static BufferedImage createSampleScreenshot(String sender, String message) {
        int width = 460;
        Font textFont = new Font(Font.SANS_SERIF, Font.PLAIN, 16);
        BufferedImage measure = new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
        Graphics2D m = measure.createGraphics();
        List<String> lines = wrapText(message, m.getFontMetrics(textFont), width - 110);
        m.dispose();

        int bubbleHeight = lines.size() * 23 + 26;
        int height = 92 + bubbleHeight + 60;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2 = image.createGraphics();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        g2.setColor(new Color(243, 244, 247));
        g2.fillRect(0, 0, width, height);
        g2.setColor(Color.WHITE);
        g2.fillRect(0, 0, width, 64);
        g2.setColor(new Color(226, 229, 235));
        g2.fillRect(0, 64, width, 1);

        g2.setColor(new Color(148, 163, 184));
        g2.fillOval(18, 14, 36, 36);
        g2.setColor(Color.WHITE);
        g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 17));
        String initial = sender.substring(0, 1).toUpperCase(Locale.ROOT);
        FontMetrics initialFm = g2.getFontMetrics();
        g2.drawString(initial, 36 - initialFm.stringWidth(initial) / 2, 38);
        g2.setColor(new Color(17, 24, 39));
        g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 16));
        g2.drawString(sender, 66, 32);
        g2.setColor(new Color(107, 114, 128));
        g2.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        g2.drawString("Text message  -  Today 09:41", 66, 50);

        g2.setColor(new Color(229, 231, 235));
        g2.fill(new RoundRectangle2D.Double(18, 84, width - 70, bubbleHeight, 22, 22));
        g2.setColor(new Color(17, 24, 39));
        g2.setFont(textFont);
        int y = 84 + 30;
        for (String line : lines) {
            g2.drawString(line, 34, y);
            y += 23;
        }
        g2.setColor(new Color(156, 163, 175));
        g2.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        g2.drawString("Delivered", 22, 84 + bubbleHeight + 20);
        g2.dispose();
        return image;
    }

    private static List<String> wrapText(String text, FontMetrics fm, int maxWidth) {
        List<String> lines = new ArrayList<>();
        StringBuilder line = new StringBuilder();
        for (String word : text.split(" ")) {
            String candidate = line.length() == 0 ? word : line + " " + word;
            if (fm.stringWidth(candidate) > maxWidth && line.length() > 0) {
                lines.add(line.toString());
                line = new StringBuilder(word);
            } else {
                line = new StringBuilder(candidate);
            }
        }
        if (line.length() > 0) {
            lines.add(line.toString());
        }
        return lines;
    }

    /** Shows the selected image scaled to fit, or a dashed drop-zone when empty. */
    private static class ImagePreview extends JComponent {
        private BufferedImage image;

        ImagePreview() {
            setPreferredSize(new Dimension(200, 150));
            setMinimumSize(new Dimension(100, 100));
        }

        void setImage(BufferedImage image) {
            this.image = image;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Main.smooth(g);
            g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
            int w = getWidth();
            int h = getHeight();
            RoundRectangle2D box = new RoundRectangle2D.Double(0.5, 0.5, w - 2, h - 2, 16, 16);
            g2.setColor(Main.BG_INPUT);
            g2.fill(box);

            if (image == null) {
                g2.setColor(Main.withAlpha(Main.CYAN, 90));
                g2.setStroke(new BasicStroke(1.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 10f, new float[]{7f, 6f}, 0f));
                g2.draw(new RoundRectangle2D.Double(1.5, 1.5, w - 4, h - 4, 16, 16));
                Main.drawIcon(g2, "image", w / 2 - 18, h / 2 - 40, 36, Main.withAlpha(Main.CYAN, 200));
                g2.setFont(Main.font(Font.BOLD, 14));
                FontMetrics fm = g2.getFontMetrics();
                String title = "No image uploaded";
                g2.setColor(Main.TEXT);
                g2.drawString(title, (w - fm.stringWidth(title)) / 2, h / 2 + 18);
                g2.setFont(Main.font(Font.PLAIN, 12.5f));
                fm = g2.getFontMetrics();
                String hint = "Click \"Upload Image\" to preview a JPG, JPEG or PNG";
                g2.setColor(Main.TEXT_MUTED);
                g2.drawString(hint, (w - fm.stringWidth(hint)) / 2, h / 2 + 38);
            } else {
                int pad = 10;
                double scale = Math.min((w - pad * 2) / (double) image.getWidth(), (h - pad * 2) / (double) image.getHeight());
                scale = Math.min(scale, 1.0); // never enlarge small images
                int iw = (int) (image.getWidth() * scale);
                int ih = (int) (image.getHeight() * scale);
                int x = (w - iw) / 2;
                int y = (h - ih) / 2;
                g2.setClip(new RoundRectangle2D.Double(x, y, iw, ih, 10, 10));
                g2.drawImage(image, x, y, iw, ih, null);
                g2.setClip(null);
                g2.setColor(Main.BORDER);
                g2.draw(new RoundRectangle2D.Double(x, y, iw, ih, 10, 10));
                g2.setColor(Main.BORDER);
                g2.draw(box);
            }
            g2.dispose();
        }
    }
}
