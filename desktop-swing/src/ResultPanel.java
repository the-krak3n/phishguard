import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.border.EmptyBorder;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagLayout;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.geom.Arc2D;
import java.awt.geom.Line2D;
import java.awt.geom.RoundRectangle2D;

/**
 * ResultPanel shows the result of one scan in a clear, visual way:
 *   - an animated circular risk gauge (0 - 100)
 *   - the classification (LOW RISK / SUSPICIOUS / HIGH RISK)
 *   - a horizontal risk bar
 *   - the reasons that increased the score
 *   - the links that were found
 *   - recommended safety actions
 *
 * It is used on the Email, Image and Voice pages.
 * The CircularGauge and RiskBar classes are also reused by the dashboard.
 */
public class ResultPanel extends JPanel {

    private final CardLayout cards = new CardLayout();
    private final Main.ScrollablePanel column = new Main.ScrollablePanel(null);
    private final JScrollPane scrollPane;

    private final CircularGauge gauge = new CircularGauge(150);
    private final Main.Pill classificationPill = new Main.Pill("LOW RISK", Main.GREEN);
    private final JLabel headlineLabel = Main.createLabel("", Main.font(Font.BOLD, 19), Main.TEXT);
    private final JTextArea descriptionText = createWrappedText("", Main.font(Font.PLAIN, 13), Main.TEXT_MUTED);
    private final RiskBar riskBar = new RiskBar();
    private final JLabel scoreLabel = Main.createLabel("", Main.font(Font.BOLD, 12), Main.TEXT_MUTED);

    private final JPanel reasonsList = createList();
    private final JPanel urlsList = createList();
    private final JPanel recommendationsList = createList();
    private final SectionHeader reasonsHeader = new SectionHeader("Why this was flagged", "alert");
    private final SectionHeader urlsHeader = new SectionHeader("Detected URLs", "link");
    private final SectionHeader recommendationsHeader = new SectionHeader("Recommended actions", "check");
    private final JPanel urlsSection = new JPanel();

    public ResultPanel() {
        setOpaque(false);
        setLayout(cards);

        column.setLayout(new BoxLayout(column, BoxLayout.Y_AXIS));
        column.setBorder(new EmptyBorder(0, 0, 10, 10));
        column.add(createSummaryCard());
        column.add(Box.createVerticalStrut(22));
        column.add(createSection(reasonsHeader, reasonsList));
        column.add(Box.createVerticalStrut(22));
        urlsSection.setOpaque(false);
        urlsSection.setLayout(new BoxLayout(urlsSection, BoxLayout.Y_AXIS));
        urlsSection.setAlignmentX(Component.LEFT_ALIGNMENT);
        urlsSection.add(createSection(urlsHeader, urlsList));
        urlsSection.add(Box.createVerticalStrut(22));
        column.add(urlsSection);
        column.add(createSection(recommendationsHeader, recommendationsList));

        // Text areas need a second layout pass after the width changes so wrapped text gets its full height.
        column.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                SwingUtilities.invokeLater(column::revalidate);
            }
        });

        scrollPane = Main.createScrollPane(column, null);
        add(createEmptyState(), "empty");
        add(scrollPane, "result");
        cards.show(this, "empty");
    }

    /** Fills the panel with a scan result and animates the gauge. */
    public void showResult(PhishingDetector.Result result) {
        Color color = Main.classificationColor(result.classification);

        gauge.setScore(result.score, true);
        classificationPill.setPill(result.classification, color);
        riskBar.setScore(result.score);
        scoreLabel.setText("Risk score  " + result.score + " / 100");

        if (result.classification.equals(PhishingDetector.HIGH_RISK)) {
            headlineLabel.setText("Likely phishing");
            descriptionText.setText("Several strong warning signs were found. Treat this " + noun(result.modality) + " as a scam.");
        } else if (result.classification.equals(PhishingDetector.SUSPICIOUS)) {
            headlineLabel.setText("Be careful");
            descriptionText.setText("Some warning signs were found. Verify the " + noun(result.modality) + " before you act on it.");
        } else {
            headlineLabel.setText("Looks safe");
            descriptionText.setText("No strong phishing indicators were found in this " + noun(result.modality) + ".");
        }

        // ---- Reasons ----
        reasonsList.removeAll();
        for (String note : result.notes) {
            addRow(reasonsList, new ListRow("info", Main.BLUE, null, note, null, null, false));
        }
        for (PhishingDetector.Indicator indicator : result.indicators) {
            Color pointsColor = pointsColor(indicator.points);
            String chip = (indicator.points > 0 ? "+" : "") + indicator.points;
            addRow(reasonsList, new ListRow(indicator.points < 0 ? "check" : "alert", pointsColor,
                    indicator.title, indicator.detail, chip, pointsColor, false));
        }
        reasonsHeader.setCount(result.positiveIndicatorCount());

        // ---- URLs (not shown for voice calls) ----
        boolean showUrls = !result.modality.equals(PhishingDetector.VOICE) || !result.urls.isEmpty();
        urlsSection.setVisible(showUrls);
        urlsList.removeAll();
        if (result.urls.isEmpty()) {
            addRow(urlsList, new ListRow("info", Main.TEXT_DIM, null, "No links were found in the text.", null, null, false));
        }
        for (PhishingDetector.UrlFinding url : result.urls) {
            if (url.isSuspicious()) {
                addRow(urlsList, new ListRow("link", Main.RED, url.url, "Problems: " + String.join("; ", url.issues),
                        "UNSAFE", Main.RED, true));
            } else {
                addRow(urlsList, new ListRow("link", Main.GREEN, url.url, "No problems found with this link.",
                        "OK", Main.GREEN, true));
            }
        }
        urlsHeader.setCount(result.suspiciousUrlCount());

        // ---- Recommendations ----
        recommendationsList.removeAll();
        for (String tip : result.recommendations) {
            addRow(recommendationsList, new ListRow("tick", Main.CYAN, null, tip, null, null, false));
        }
        recommendationsHeader.setCount(result.recommendations.size());

        cards.show(this, "result");
        SwingUtilities.invokeLater(() -> scrollPane.getVerticalScrollBar().setValue(0));
        relayoutTwice();
    }

    /** Back to the empty "no analysis yet" state. */
    public void clear() {
        cards.show(this, "empty");
    }

    // ------------------------------------------------------------------
    // Building blocks
    // ------------------------------------------------------------------

    private JComponent createSummaryCard() {
        Main.RoundedPanel card = new Main.RoundedPanel(new BorderLayout(20, 0), 18, Main.BG_CARD_ALT, Main.BORDER);
        card.setBorder(new EmptyBorder(16, 16, 16, 20));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(gauge, BorderLayout.WEST);

        JPanel info = new JPanel();
        info.setOpaque(false);
        info.setLayout(new BoxLayout(info, BoxLayout.Y_AXIS));

        JLabel caption = Main.createLabel("RISK ASSESSMENT", Main.tracked(Main.font(Font.BOLD, 11), 0.1f), Main.TEXT_DIM);
        JPanel pillRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        pillRow.setOpaque(false);
        pillRow.add(classificationPill);

        riskBar.setPreferredSize(new Dimension(100, 10));
        riskBar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 10));

        for (JComponent c : new JComponent[]{caption, pillRow, headlineLabel, descriptionText, scoreLabel, riskBar}) {
            c.setAlignmentX(Component.LEFT_ALIGNMENT);
        }
        pillRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));

        info.add(Box.createVerticalGlue());
        info.add(caption);
        info.add(Box.createVerticalStrut(8));
        info.add(pillRow);
        info.add(Box.createVerticalStrut(10));
        info.add(headlineLabel);
        info.add(Box.createVerticalStrut(4));
        info.add(descriptionText);
        info.add(Box.createVerticalStrut(12));
        info.add(scoreLabel);
        info.add(Box.createVerticalStrut(7));
        info.add(riskBar);
        info.add(Box.createVerticalGlue());
        card.add(info, BorderLayout.CENTER);
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 240));
        return card;
    }

    private JComponent createSection(SectionHeader header, JPanel list) {
        JPanel section = new JPanel();
        section.setOpaque(false);
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.setAlignmentX(Component.LEFT_ALIGNMENT);
        list.setAlignmentX(Component.LEFT_ALIGNMENT);
        section.add(header);
        section.add(Box.createVerticalStrut(10));
        section.add(list);
        return section;
    }

    private JComponent createEmptyState() {
        JPanel empty = new JPanel(new GridBagLayout());
        empty.setOpaque(false);
        JPanel box = new JPanel();
        box.setOpaque(false);
        box.setLayout(new BoxLayout(box, BoxLayout.Y_AXIS));

        Main.IconBadge badge = new Main.IconBadge("scan", 72, Main.CYAN);
        badge.setAlignmentX(Component.CENTER_ALIGNMENT);
        box.add(badge);
        box.add(Box.createVerticalStrut(18));
        box.add(Main.createCenteredLabel("No analysis yet", Main.font(Font.BOLD, 18), Main.TEXT));
        box.add(Box.createVerticalStrut(8));
        box.add(Main.createCenteredLabel("Fill in the details on the left and press the scan button.", Main.font(Font.PLAIN, 13), Main.TEXT_MUTED));
        box.add(Box.createVerticalStrut(2));
        box.add(Main.createCenteredLabel("The risk score, reasons and safety tips will appear here.", Main.font(Font.PLAIN, 13), Main.TEXT_MUTED));
        empty.add(box);
        return empty;
    }

    private static JPanel createList() {
        JPanel list = new JPanel();
        list.setOpaque(false);
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));
        return list;
    }

    private static void addRow(JPanel list, JComponent row) {
        if (list.getComponentCount() > 0) {
            list.add(Box.createVerticalStrut(8));
        }
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        list.add(row);
    }

    /** Wrapped text areas get their correct height only after a first layout, so layout twice. */
    private void relayoutTwice() {
        column.revalidate();
        column.repaint();
        SwingUtilities.invokeLater(() -> {
            column.revalidate();
            column.repaint();
        });
    }

    private static Color pointsColor(int points) {
        if (points < 0) {
            return Main.GREEN;
        }
        if (points >= 15) {
            return Main.RED;
        }
        if (points >= 8) {
            return Main.ORANGE;
        }
        return Main.CYAN;
    }

    private static String noun(String modality) {
        switch (modality) {
            case PhishingDetector.EMAIL:
                return "email";
            case PhishingDetector.IMAGE:
                return "image";
            case PhishingDetector.VOICE:
                return "call";
            default:
                return "content";
        }
    }

    /** A read-only text block that wraps lines like a paragraph. */
    static JTextArea createWrappedText(String text, Font font, Color color) {
        JTextArea area = new JTextArea(text);
        area.setFont(font);
        area.setForeground(color);
        area.setOpaque(false);
        area.setEditable(false);
        area.setFocusable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(null);
        area.setHighlighter(null);
        return area;
    }

    // =====================================================================
    // Small inner components
    // =====================================================================

    /** Title of a result section with an icon and a counter on the right. */
    private static class SectionHeader extends JPanel {
        private final Main.Pill countPill = new Main.Pill("0", Main.TEXT_MUTED);

        SectionHeader(String title, String iconName) {
            super(new BorderLayout());
            setOpaque(false);
            JLabel label = Main.createLabel(title, Main.font(Font.BOLD, 15), Main.TEXT);
            label.setIcon(Main.icon(iconName, 17, Main.CYAN));
            label.setIconTextGap(9);
            add(label, BorderLayout.WEST);
            add(countPill, BorderLayout.EAST);
            setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        }

        void setCount(int count) {
            countPill.setPill(String.valueOf(count), count > 0 ? Main.CYAN : Main.TEXT_DIM);
        }
    }

    /** One row inside a result list: icon, title, detail text and an optional chip (like "+18"). */
    private static class ListRow extends Main.RoundedPanel {
        ListRow(String iconName, Color iconColor, String title, String detail, String chip, Color chipColor, boolean titleIsUrl) {
            super(new BorderLayout(12, 0), 14, new Color(14, 22, 41), new Color(30, 43, 70));
            setBorder(new EmptyBorder(11, 12, 11, 12));

            JComponent icon = new JComponent() {
                @Override
                protected void paintComponent(Graphics g) {
                    Graphics2D g2 = Main.smooth(g);
                    g2.setColor(Main.withAlpha(iconColor, 34));
                    g2.fillRoundRect(0, 0, 28, 28, 10, 10);
                    Main.drawIcon(g2, iconName, 6, 6, 16, iconColor);
                    g2.dispose();
                }
            };
            icon.setPreferredSize(new Dimension(28, 28));
            JPanel iconWrap = new JPanel(new BorderLayout());
            iconWrap.setOpaque(false);
            iconWrap.add(icon, BorderLayout.NORTH);
            add(iconWrap, BorderLayout.WEST);

            JPanel texts = new JPanel();
            texts.setOpaque(false);
            texts.setLayout(new BoxLayout(texts, BoxLayout.Y_AXIS));
            if (title != null) {
                JTextArea titleText = createWrappedText(title,
                        titleIsUrl ? new Font(Font.MONOSPACED, Font.PLAIN, 13) : Main.font(Font.BOLD, 13.5f), Main.TEXT);
                titleText.setWrapStyleWord(!titleIsUrl); // long links may break anywhere
                titleText.setAlignmentX(Component.LEFT_ALIGNMENT);
                texts.add(titleText);
                texts.add(Box.createVerticalStrut(3));
            }
            JTextArea detailText = createWrappedText(detail, Main.font(Font.PLAIN, 12.5f),
                    title == null ? new Color(200, 210, 230) : Main.TEXT_MUTED);
            detailText.setAlignmentX(Component.LEFT_ALIGNMENT);
            texts.add(detailText);
            add(texts, BorderLayout.CENTER);

            if (chip != null) {
                Main.Pill pill = new Main.Pill(chip, chipColor);
                JPanel chipWrap = new JPanel(new BorderLayout());
                chipWrap.setOpaque(false);
                chipWrap.add(pill, BorderLayout.NORTH);
                add(chipWrap, BorderLayout.EAST);
            }
        }

        @Override
        public Dimension getMaximumSize() {
            return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
        }
    }

    /** Animated half-open ring that shows a score from 0 to 100. Score -1 means "no data". */
    public static class CircularGauge extends JComponent {
        private int targetScore = -1;
        private float shownScore = 0;
        private final Timer timer;

        public CircularGauge(int diameter) {
            setPreferredSize(new Dimension(diameter, diameter));
            setMinimumSize(new Dimension(diameter, diameter));
            timer = new Timer(16, e -> animateStep());
        }

        public void setScore(int score, boolean animate) {
            targetScore = score;
            if (score < 0 || !animate) {
                timer.stop();
                shownScore = Math.max(score, 0);
                repaint();
            } else {
                shownScore = 0;
                timer.restart();
            }
        }

        private void animateStep() {
            float difference = targetScore - shownScore;
            if (Math.abs(difference) < 0.6f) {
                shownScore = targetScore;
                timer.stop();
            } else {
                shownScore += difference * 0.12f + Math.signum(difference) * 0.4f;
            }
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Main.smooth(g);
            int size = Math.min(getWidth(), getHeight()) - 6;
            float stroke = Math.max(8f, size * 0.085f);
            double x = (getWidth() - size) / 2.0 + stroke / 2;
            double y = (getHeight() - size) / 2.0 + stroke / 2;
            double d = size - stroke;

            // tick marks around the ring
            g2.setStroke(new BasicStroke(1.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            double cx = getWidth() / 2.0;
            double cy = getHeight() / 2.0;
            double outer = size / 2.0 + 1;
            for (int i = 0; i <= 10; i++) {
                double angle = Math.toRadians(225 - 27 * i);
                double inner = outer - (i % 5 == 0 ? 6 : 3.5);
                g2.setColor(Main.withAlpha(Main.TEXT_MUTED, 80));
                g2.draw(new Line2D.Double(cx + Math.cos(angle) * inner, cy - Math.sin(angle) * inner,
                        cx + Math.cos(angle) * outer, cy - Math.sin(angle) * outer));
            }

            double inset = 8;
            Arc2D track = new Arc2D.Double(x + inset, y + inset, d - inset * 2, d - inset * 2, 225, -270, Arc2D.OPEN);
            g2.setStroke(new BasicStroke(stroke, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.setColor(new Color(33, 46, 75));
            g2.draw(track);

            Color color = targetScore < 0 ? Main.TEXT_DIM : Main.riskColor(Math.round(shownScore));
            if (targetScore >= 0 && shownScore > 0.5f) {
                double extent = -270 * shownScore / 100.0;
                Arc2D value = new Arc2D.Double(x + inset, y + inset, d - inset * 2, d - inset * 2, 225, extent, Arc2D.OPEN);
                g2.setStroke(new BasicStroke(stroke + 7, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.setColor(Main.withAlpha(color, 40)); // soft glow
                g2.draw(value);
                g2.setStroke(new BasicStroke(stroke, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.setColor(color);
                g2.draw(value);
            }

            // number in the middle
            String number = targetScore < 0 ? "--" : String.valueOf(Math.round(shownScore));
            g2.setFont(Main.font(Font.BOLD, size * 0.27f));
            FontMetrics fm = g2.getFontMetrics();
            g2.setColor(Main.TEXT);
            int numberY = (int) (cy + fm.getAscent() * 0.32);
            g2.drawString(number, (int) (cx - fm.stringWidth(number) / 2.0), numberY);

            g2.setFont(Main.font(Font.BOLD, Math.max(10f, size * 0.075f)));
            FontMetrics small = g2.getFontMetrics();
            String caption = targetScore < 0 ? "NO DATA" : "/ 100";
            g2.setColor(targetScore < 0 ? Main.TEXT_DIM : color);
            g2.drawString(caption, (int) (cx - small.stringWidth(caption) / 2.0), numberY + small.getHeight() + 2);
            g2.dispose();
        }
    }

    /** Horizontal progress bar colored green / orange / red by score. Score -1 shows an empty track. */
    public static class RiskBar extends JComponent {
        private int score = -1;

        public RiskBar() {
            setPreferredSize(new Dimension(120, 8));
        }

        public void setScore(int score) {
            this.score = score;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Main.smooth(g);
            int h = Math.min(getHeight(), 10);
            int y = (getHeight() - h) / 2;
            int w = getWidth();
            g2.setColor(new Color(33, 46, 75));
            g2.fill(new RoundRectangle2D.Double(0, y, w, h, h, h));
            if (score > 0) {
                Color color = Main.riskColor(score);
                int fill = Math.max(h, (int) (w * Math.min(score, 100) / 100.0));
                g2.setPaint(new GradientPaint(0, 0, Main.withAlpha(color, 150), fill, 0, color));
                g2.fill(new RoundRectangle2D.Double(0, y, fill, h, h, h));
            }
            g2.dispose();
        }
    }
}
