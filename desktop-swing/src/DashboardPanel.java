import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.RadialGradientPaint;
import java.awt.geom.Arc2D;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.awt.geom.RoundRectangle2D;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * DashboardPanel - the home screen.
 *
 * Shows:
 *   - a welcome banner
 *   - four statistic cards (total, phishing, suspicious, safe)
 *   - the MULTIMODAL threat assessment (latest Email + Image + Voice scores and their average)
 *   - a donut chart of the risk distribution
 *   - recent scan activity
 *   - a bar chart of scans by type
 *
 * The charts are drawn with plain Java 2D, so no chart library is needed.
 */
public class DashboardPanel extends JPanel {

    private final Main app;

    private final StatCard totalCard = new StatCard("Total Scans", "target", Main.CYAN);
    private final StatCard phishingCard = new StatCard("Phishing Detected", "alert", Main.RED);
    private final StatCard suspiciousCard = new StatCard("Suspicious", "info", Main.ORANGE);
    private final StatCard safeCard = new StatCard("Safe Scans", "check", Main.GREEN);

    private final DonutChart donutChart = new DonutChart();
    private final BarChart barChart = new BarChart();
    private final JPanel recentList = new JPanel();

    // Multimodal section
    private final ResultPanel.CircularGauge overallGauge = new ResultPanel.CircularGauge(160);
    private final ModalityRow emailRow = new ModalityRow(PhishingDetector.EMAIL);
    private final ModalityRow imageRow = new ModalityRow(PhishingDetector.IMAGE);
    private final ModalityRow voiceRow = new ModalityRow(PhishingDetector.VOICE);
    private final Main.Pill overallPill = new Main.Pill("AWAITING SCANS", Main.TEXT_DIM);
    private final JLabel formulaLabel = Main.createLabel("", Main.font(Font.PLAIN, 13), Main.TEXT_MUTED);
    private final JPanel indicatorList = new JPanel(new GridLayout(0, 2, 18, 8));
    private final Main.ModernButton saveButton = new Main.ModernButton("Save Report", "save", Main.ModernButton.Style.PRIMARY);
    private final Main.ModernButton resetButton = new Main.ModernButton("Reset Session", "refresh", Main.ModernButton.Style.SECONDARY);
    private PhishingDetector.Result combinedResult;

    public DashboardPanel(Main app) {
        this.app = app;
        setLayout(new BorderLayout());
        setBackground(Main.BG_APP);

        Main.ScrollablePanel content = new Main.ScrollablePanel(new GridBagLayout());
        content.setBorder(new EmptyBorder(28, 32, 32, 32));

        GridBagConstraints gc = new GridBagConstraints();
        gc.fill = GridBagConstraints.BOTH;
        gc.gridx = 0;
        gc.gridy = 0;
        gc.gridwidth = 2;
        gc.weightx = 1;
        gc.insets = new Insets(0, 0, 22, 0);
        content.add(withSmallWidth(createWelcomeBanner()), gc);

        gc.gridy = 1;
        content.add(withSmallWidth(createStatsRow()), gc);

        gc.gridy = 2;
        gc.gridwidth = 1;
        gc.weightx = 0.6;
        gc.insets = new Insets(0, 0, 22, 22);
        content.add(createMultimodalCard(), gc);

        gc.gridx = 1;
        gc.weightx = 0.4;
        gc.insets = new Insets(0, 0, 22, 0);
        content.add(createChartCard("Risk Distribution", "Share of all saved scans", "pie", donutChart), gc);

        gc.gridx = 0;
        gc.gridy = 3;
        gc.weightx = 0.6;
        gc.insets = new Insets(0, 0, 0, 22);
        content.add(createRecentCard(), gc);

        gc.gridx = 1;
        gc.weightx = 0.4;
        gc.insets = new Insets(0, 0, 0, 0);
        content.add(createChartCard("Scans by Type", "How often each scanner was used", "bars", barChart), gc);

        add(Main.createScrollPane(content, Main.BG_APP), BorderLayout.CENTER);

        saveButton.addActionListener(e -> saveCombinedReport());
        resetButton.addActionListener(e -> app.resetSession());
        refresh();
    }

    /** Reloads all numbers and charts from the history file and the current session. */
    public void refresh() {
        List<HistoryManager.ScanRecord> records = app.getHistoryManager().loadAll();
        int total = records.size();
        int high = 0;
        int suspicious = 0;
        int low = 0;
        int[] byType = new int[4];
        for (HistoryManager.ScanRecord record : records) {
            if (PhishingDetector.HIGH_RISK.equals(record.classification)) {
                high++;
            } else if (PhishingDetector.SUSPICIOUS.equals(record.classification)) {
                suspicious++;
            } else {
                low++;
            }
            byType[typeIndex(record.scanType)]++;
        }

        totalCard.setData(total, total == 0 ? "No scans saved yet" : "Saved in scan_history.csv", total == 0 ? 0 : 1);
        phishingCard.setData(high, percent(high, total) + " of all scans", ratio(high, total));
        suspiciousCard.setData(suspicious, percent(suspicious, total) + " of all scans", ratio(suspicious, total));
        safeCard.setData(low, percent(low, total) + " of all scans", ratio(low, total));
        donutChart.setValues(high, suspicious, low);
        barChart.setValues(byType);

        List<HistoryManager.ScanRecord> newestFirst = new ArrayList<>(records);
        Collections.reverse(newestFirst);
        rebuildRecentList(newestFirst);
        updateMultimodalSection();

        revalidate();
        repaint();
    }

    // =====================================================================
    // Sections
    // =====================================================================

    private JComponent createWelcomeBanner() {
        JPanel banner = new JPanel(new BorderLayout(24, 0)) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = Main.smooth(g);
                int w = getWidth();
                int h = getHeight();
                RoundRectangle2D shape = new RoundRectangle2D.Double(0, 0, w - 1, h - 1, 22, 22);
                g2.setPaint(new GradientPaint(0, 0, new Color(13, 47, 86), w, h, new Color(16, 24, 46)));
                g2.fill(shape);
                g2.clip(shape);

                // decorative radar on the right side
                double cx = w - 170;
                double cy = h + 30;
                for (int r = 50; r < 460; r += 40) {
                    g2.setColor(Main.withAlpha(Main.CYAN, Math.max(8, 46 - r / 10)));
                    g2.draw(new Ellipse2D.Double(cx - r, cy - r, r * 2, r * 2));
                }
                g2.setPaint(new RadialGradientPaint((float) cx, (float) cy, 330f, new float[]{0f, 1f},
                        new Color[]{Main.withAlpha(Main.CYAN, 70), Main.withAlpha(Main.CYAN, 0)}));
                g2.fill(new Arc2D.Double(cx - 330, cy - 330, 660, 660, 98, 34, Arc2D.PIE));
                drawBlip(g2, cx - 120, cy - 128, Main.RED);
                drawBlip(g2, cx + 70, cy - 92, Main.GREEN);
                drawBlip(g2, cx - 30, cy - 175, Main.ORANGE);

                g2.setClip(null);
                g2.setColor(Main.withAlpha(Main.CYAN, 55));
                g2.draw(shape);
                g2.dispose();
            }
        };
        banner.setOpaque(false);
        banner.setBorder(new EmptyBorder(26, 30, 26, 30));

        JPanel texts = new JPanel();
        texts.setOpaque(false);
        texts.setLayout(new BoxLayout(texts, BoxLayout.Y_AXIS));
        JLabel welcome = Main.createLabel("WELCOME BACK", Main.tracked(Main.font(Font.BOLD, 11.5f), 0.14f), Main.CYAN);
        JLabel title = Main.createLabel("Multimodal Phishing Detection", Main.font(Font.BOLD, 28), Main.TEXT);
        JLabel line1 = Main.createLabel("Analyse email text, embedded images and voice-call transcripts for phishing and scams.",
                Main.font(Font.PLAIN, 14), new Color(176, 190, 216));
        JLabel line2 = Main.createLabel("Each scan receives a 0-100 risk score with clear reasons and is saved to your scan history.",
                Main.font(Font.PLAIN, 14), new Color(176, 190, 216));
        texts.add(welcome);
        texts.add(Box.createVerticalStrut(8));
        texts.add(title);
        texts.add(Box.createVerticalStrut(8));
        texts.add(line1);
        texts.add(Box.createVerticalStrut(2));
        texts.add(line2);
        banner.add(texts, BorderLayout.CENTER);

        JPanel side = new JPanel();
        side.setOpaque(false);
        side.setLayout(new BoxLayout(side, BoxLayout.Y_AXIS));
        Main.Pill status = new Main.Pill("ENGINE ACTIVE", Main.GREEN);
        status.setAlignmentX(Component.RIGHT_ALIGNMENT);
        String today = LocalDate.now().format(DateTimeFormatter.ofPattern("EEEE, d MMMM yyyy", Locale.ENGLISH));
        JLabel date = Main.createLabel(today, Main.font(Font.PLAIN, 13), Main.TEXT_MUTED);
        date.setIcon(Main.icon("calendar", 15, Main.TEXT_MUTED));
        date.setIconTextGap(8);
        date.setAlignmentX(Component.RIGHT_ALIGNMENT);
        side.add(status);
        side.add(Box.createVerticalStrut(12));
        side.add(date);
        banner.add(side, BorderLayout.EAST);
        return banner;
    }

    private static void drawBlip(Graphics2D g2, double x, double y, Color color) {
        g2.setColor(Main.withAlpha(color, 50));
        g2.fill(new Ellipse2D.Double(x - 7, y - 7, 14, 14));
        g2.setColor(color);
        g2.fill(new Ellipse2D.Double(x - 3, y - 3, 6, 6));
    }

    private JComponent createStatsRow() {
        JPanel row = new JPanel(new GridLayout(1, 4, 18, 0));
        row.setOpaque(false);
        row.add(totalCard);
        row.add(phishingCard);
        row.add(suspiciousCard);
        row.add(safeCard);
        return row;
    }

    private JComponent createMultimodalCard() {
        Main.RoundedPanel card = new Main.RoundedPanel(new BorderLayout(0, 18));
        card.setBorder(new EmptyBorder(22, 24, 22, 24));
        card.setPreferredWidthHint(100);

        JPanel header = new JPanel(new BorderLayout(12, 0));
        header.setOpaque(false);
        header.add(createCardTitleBlock("Multimodal Threat Assessment", "Simple average of your latest scans", "layers"),
                BorderLayout.CENTER);
        JPanel pillWrap = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 4));
        pillWrap.setOpaque(false);
        pillWrap.add(overallPill);
        header.add(pillWrap, BorderLayout.EAST);

        JPanel body = new JPanel(new BorderLayout(26, 0));
        body.setOpaque(false);
        body.add(overallGauge, BorderLayout.WEST);
        JPanel rows = new JPanel();
        rows.setOpaque(false);
        rows.setLayout(new BoxLayout(rows, BoxLayout.Y_AXIS));
        rows.add(Box.createVerticalGlue());
        for (ModalityRow row : new ModalityRow[]{emailRow, imageRow, voiceRow}) {
            row.setAlignmentX(Component.LEFT_ALIGNMENT);
            rows.add(row);
            rows.add(Box.createVerticalStrut(12));
        }
        formulaLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        formulaLabel.setBorder(new EmptyBorder(6, 0, 0, 0));
        rows.add(formulaLabel);
        rows.add(Box.createVerticalGlue());
        body.add(rows, BorderLayout.CENTER);

        JPanel footer = new JPanel();
        footer.setOpaque(false);
        footer.setLayout(new BoxLayout(footer, BoxLayout.Y_AXIS));
        JLabel caption = Main.createFieldLabel("Key indicators across modalities");
        caption.setAlignmentX(Component.LEFT_ALIGNMENT);
        indicatorList.setOpaque(false);
        indicatorList.setAlignmentX(Component.LEFT_ALIGNMENT);
        JPanel buttons = Main.createButtonRow(saveButton, resetButton);
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        footer.add(createDivider());
        footer.add(Box.createVerticalStrut(16));
        footer.add(caption);
        footer.add(Box.createVerticalStrut(4));
        footer.add(indicatorList);
        footer.add(Box.createVerticalStrut(18));
        footer.add(buttons);

        card.add(header, BorderLayout.NORTH);
        card.add(body, BorderLayout.CENTER);
        card.add(footer, BorderLayout.SOUTH);
        return card;
    }

    private JComponent createChartCard(String title, String subtitle, String iconName, JComponent chart) {
        Main.RoundedPanel card = new Main.RoundedPanel(new BorderLayout(0, 16));
        card.setBorder(new EmptyBorder(22, 24, 20, 24));
        card.setPreferredWidthHint(100);
        card.add(createCardTitleBlock(title, subtitle, iconName), BorderLayout.NORTH);
        card.add(chart, BorderLayout.CENTER);
        return card;
    }

    private JComponent createRecentCard() {
        Main.RoundedPanel card = new Main.RoundedPanel(new BorderLayout(0, 10));
        card.setBorder(new EmptyBorder(22, 24, 14, 24));
        card.setPreferredWidthHint(100);

        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);
        header.add(createCardTitleBlock("Recent Activity", "Latest scans saved to history", "activity"), BorderLayout.CENTER);
        Main.ModernButton viewAll = new Main.ModernButton("View all", "history", Main.ModernButton.Style.GHOST);
        viewAll.addActionListener(e -> app.showPage(Main.PAGE_HISTORY));
        header.add(viewAll, BorderLayout.EAST);

        recentList.setOpaque(false);
        recentList.setLayout(new BoxLayout(recentList, BoxLayout.Y_AXIS));
        card.add(header, BorderLayout.NORTH);
        card.add(recentList, BorderLayout.CENTER);
        return card;
    }

    /** Card title with an icon and a muted subtitle below it. */
    private static JComponent createCardTitleBlock(String title, String subtitle, String iconName) {
        JPanel block = new JPanel(new GridLayout(2, 1, 0, 2));
        block.setOpaque(false);
        block.add(Main.createCardTitle(title, iconName));
        JLabel sub = Main.createLabel(subtitle, Main.font(Font.PLAIN, 12.5f), Main.TEXT_MUTED);
        sub.setBorder(new EmptyBorder(0, 28, 0, 0));
        block.add(sub);
        return block;
    }

    /**
     * GridBagLayout switches to "minimum size" mode (and squashes everything) when a row asks for
     * more width than the window has. A small preferred width keeps it in normal mode on small screens.
     */
    private static JComponent withSmallWidth(JComponent component) {
        component.setPreferredSize(new Dimension(100, component.getPreferredSize().height));
        return component;
    }

    private static JComponent createDivider() {
        JComponent line = new JComponent() {
            @Override
            protected void paintComponent(Graphics g) {
                g.setColor(Main.BORDER);
                g.fillRect(0, 0, getWidth(), 1);
            }
        };
        line.setAlignmentX(Component.LEFT_ALIGNMENT);
        line.setPreferredSize(new Dimension(10, 1));
        line.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        return line;
    }

    // =====================================================================
    // Updating the sections
    // =====================================================================

    private void rebuildRecentList(List<HistoryManager.ScanRecord> newestFirst) {
        recentList.removeAll();
        if (newestFirst.isEmpty()) {
            JPanel empty = new JPanel();
            empty.setOpaque(false);
            empty.setLayout(new BoxLayout(empty, BoxLayout.Y_AXIS));
            empty.setBorder(new EmptyBorder(30, 0, 30, 0));
            Main.IconBadge badge = new Main.IconBadge("activity", 54, Main.CYAN);
            badge.setAlignmentX(Component.CENTER_ALIGNMENT);
            empty.add(badge);
            empty.add(Box.createVerticalStrut(14));
            empty.add(Main.createCenteredLabel("No scans yet", Main.font(Font.BOLD, 15), Main.TEXT));
            empty.add(Box.createVerticalStrut(4));
            empty.add(Main.createCenteredLabel("Open a scanner from the sidebar to analyse your first message.",
                    Main.font(Font.PLAIN, 13), Main.TEXT_MUTED));
            empty.setAlignmentX(Component.LEFT_ALIGNMENT);
            recentList.add(empty);
            return;
        }
        int count = Math.min(5, newestFirst.size());
        for (int i = 0; i < count; i++) {
            recentList.add(createRecentRow(newestFirst.get(i), i == count - 1));
        }
    }

    private JComponent createRecentRow(HistoryManager.ScanRecord record, boolean last) {
        JPanel row = new JPanel(new BorderLayout(14, 0)) {
            @Override
            protected void paintComponent(Graphics g) {
                if (!last) {
                    g.setColor(new Color(30, 42, 68));
                    g.fillRect(0, getHeight() - 1, getWidth(), 1);
                }
            }
        };
        row.setOpaque(false);
        row.setBorder(new EmptyBorder(11, 0, 11, 0));
        row.add(new Main.IconBadge(Main.modalityIcon(record.scanType), 40, Main.modalityColor(record.scanType)), BorderLayout.WEST);

        JPanel texts = new JPanel(new GridLayout(2, 1, 0, 2));
        texts.setOpaque(false);
        texts.add(Main.createLabel(PhishingDetector.displayName(record.scanType) + " scan", Main.font(Font.BOLD, 14), Main.TEXT));
        JLabel summary = Main.createLabel(record.summary, Main.font(Font.PLAIN, 12.5f), Main.TEXT_MUTED);
        summary.setToolTipText(record.summary);
        summary.setPreferredSize(new Dimension(40, summary.getPreferredSize().height)); // allow "..." when too long
        texts.add(summary);
        row.add(texts, BorderLayout.CENTER);

        JPanel right = new JPanel();
        right.setOpaque(false);
        right.setLayout(new BoxLayout(right, BoxLayout.Y_AXIS));
        Main.Pill pill = new Main.Pill(record.classification, Main.classificationColor(record.classification));
        pill.setAlignmentX(Component.RIGHT_ALIGNMENT);
        JLabel meta = Main.createLabel("Score " + record.riskScore + "  |  " + friendlyTime(record.dateTime),
                Main.font(Font.PLAIN, 12), Main.TEXT_DIM);
        meta.setAlignmentX(Component.RIGHT_ALIGNMENT);
        right.add(pill);
        right.add(Box.createVerticalStrut(4));
        right.add(meta);
        row.add(right, BorderLayout.EAST);

        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, row.getPreferredSize().height));
        return row;
    }

    private void updateMultimodalSection() {
        PhishingDetector.Result email = app.getLatestResult(PhishingDetector.EMAIL);
        PhishingDetector.Result image = app.getLatestResult(PhishingDetector.IMAGE);
        PhishingDetector.Result voice = app.getLatestResult(PhishingDetector.VOICE);
        emailRow.setScore(email == null ? -1 : email.score);
        imageRow.setScore(image == null ? -1 : image.score);
        voiceRow.setScore(voice == null ? -1 : voice.score);

        List<PhishingDetector.Result> available = app.getLatestResults();
        combinedResult = PhishingDetector.combine(available);
        indicatorList.removeAll();

        if (combinedResult == null) {
            overallGauge.setScore(-1, false);
            overallPill.setPill("AWAITING SCANS", Main.TEXT_DIM);
            formulaLabel.setText("Run a scan to build a combined score.");
            indicatorList.add(Main.createLabel("No indicators yet.", Main.font(Font.PLAIN, 13), Main.TEXT_DIM));
            saveButton.setEnabled(false);
            resetButton.setEnabled(false);
            return;
        }

        overallGauge.setScore(combinedResult.score, true);
        overallPill.setPill(combinedResult.classification, Main.classificationColor(combinedResult.classification));

        List<String> numbers = new ArrayList<>();
        for (PhishingDetector.Result result : available) {
            numbers.add(String.valueOf(result.score));
        }
        formulaLabel.setText("Overall = (" + String.join(" + ", numbers) + ") / " + available.size()
                + " = " + combinedResult.score);

        int shown = 0;
        for (PhishingDetector.Indicator indicator : combinedResult.indicators) {
            if (shown == 4) {
                break;
            }
            Color color = indicator.points >= 15 ? Main.RED : indicator.points >= 8 ? Main.ORANGE : Main.CYAN;
            JLabel label = Main.createLabel(indicator.title, Main.font(Font.PLAIN, 13), Main.TEXT);
            label.setIcon(Main.dotIcon(color, 8));
            label.setIconTextGap(9);
            label.setToolTipText(indicator.detail);
            label.setPreferredSize(new Dimension(40, label.getPreferredSize().height)); // shows "..." when too long
            JPanel item = new JPanel(new BorderLayout(8, 0));
            item.setOpaque(false);
            item.add(label, BorderLayout.CENTER);
            item.add(Main.createLabel("+" + indicator.points, Main.font(Font.BOLD, 13), color), BorderLayout.EAST);
            indicatorList.add(item);
            shown++;
        }
        if (shown == 0) {
            indicatorList.add(Main.createLabel("No indicators - all scanned content looks safe.", Main.font(Font.PLAIN, 13), Main.GREEN));
        }
        saveButton.setEnabled(true);
        resetButton.setEnabled(true);
    }

    private void saveCombinedReport() {
        if (combinedResult == null) {
            return;
        }
        app.saveToHistory(combinedResult);
        JOptionPane.showMessageDialog(this, "The multimodal report (overall score " + combinedResult.score
                + ", " + combinedResult.classification + ") was saved to the scan history.",
                "Report saved", JOptionPane.INFORMATION_MESSAGE);
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    private static int typeIndex(String type) {
        switch (type) {
            case PhishingDetector.EMAIL:
                return 0;
            case PhishingDetector.IMAGE:
                return 1;
            case PhishingDetector.VOICE:
                return 2;
            default:
                return 3;
        }
    }

    private static String percent(int part, int total) {
        return total == 0 ? "0%" : Math.round(100.0 * part / total) + "%";
    }

    private static double ratio(int part, int total) {
        return total == 0 ? 0 : (double) part / total;
    }

    /** Shortens text with "..." so it fits in maxWidth pixels. */
    private static String fitText(String text, FontMetrics fm, int maxWidth) {
        if (fm.stringWidth(text) <= maxWidth) {
            return text;
        }
        String shorter = text;
        while (shorter.length() > 1 && fm.stringWidth(shorter + "...") > maxWidth) {
            shorter = shorter.substring(0, shorter.length() - 1);
        }
        return shorter.trim() + "...";
    }

    /** "2026-11-24 10:15:02" -> "24 Nov, 10:15" */
    static String friendlyTime(String dateTime) {
        try {
            LocalDateTime time = LocalDateTime.parse(dateTime, DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            return time.format(DateTimeFormatter.ofPattern("d MMM, HH:mm", Locale.ENGLISH));
        } catch (Exception e) {
            return dateTime;
        }
    }

    // =====================================================================
    // Custom painted components
    // =====================================================================

    /** Statistic card: title, big number, subtitle and a thin progress line. */
    private static class StatCard extends JComponent {
        private final String title;
        private final String iconName;
        private final Color color;
        private String value = "0";
        private String subtitle = "";
        private double share;

        StatCard(String title, String iconName, Color color) {
            this.title = title;
            this.iconName = iconName;
            this.color = color;
            setPreferredSize(new Dimension(200, 140));
        }

        void setData(int number, String subtitle, double share) {
            this.value = String.valueOf(number);
            this.subtitle = subtitle;
            this.share = share;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Main.smooth(g);
            int w = getWidth();
            int h = getHeight();
            RoundRectangle2D shape = new RoundRectangle2D.Double(0, 0, w - 1, h - 1, 20, 20);
            g2.setColor(Main.BG_CARD);
            g2.fill(shape);
            g2.clip(shape);
            g2.setPaint(new RadialGradientPaint(w - 30f, 10f, 120f, new float[]{0f, 1f},
                    new Color[]{Main.withAlpha(color, 46), Main.withAlpha(color, 0)}));
            g2.fillRect(0, 0, w, h);
            g2.setClip(null);
            g2.setColor(Main.BORDER);
            g2.draw(shape);

            // icon badge in the top-right corner
            int badge = 44;
            int bx = w - 22 - badge;
            RoundRectangle2D badgeShape = new RoundRectangle2D.Double(bx, 22, badge, badge, 14, 14);
            g2.setColor(Main.withAlpha(color, 38));
            g2.fill(badgeShape);
            g2.setColor(Main.withAlpha(color, 90));
            g2.draw(badgeShape);
            Main.drawIcon(g2, iconName, bx + 11, 33, 22, color);

            g2.setFont(Main.font(Font.BOLD, 13));
            g2.setColor(Main.TEXT_MUTED);
            g2.drawString(fitText(title, g2.getFontMetrics(), bx - 30), 22, 38);
            g2.setFont(Main.font(Font.BOLD, 34));
            g2.setColor(Main.TEXT);
            g2.drawString(value, 21, 84);
            g2.setFont(Main.font(Font.PLAIN, 12));
            g2.setColor(Main.TEXT_DIM);
            g2.drawString(subtitle, 22, 106);

            // share of total
            int barWidth = w - 44;
            g2.setColor(new Color(33, 46, 75));
            g2.fill(new RoundRectangle2D.Double(22, h - 20, barWidth, 4, 4, 4));
            if (share > 0) {
                g2.setPaint(new GradientPaint(22, 0, Main.withAlpha(color, 140), 22 + barWidth, 0, color));
                g2.fill(new RoundRectangle2D.Double(22, h - 20, Math.max(6, barWidth * share), 4, 4, 4));
            }
            g2.dispose();
        }
    }

    /** One line of the multimodal section: icon, name, risk bar and score. */
    private static class ModalityRow extends JComponent {
        private final String modality;
        private int score = -1;

        ModalityRow(String modality) {
            this.modality = modality;
            setPreferredSize(new Dimension(220, 30));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        }

        void setScore(int score) {
            this.score = score;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Main.smooth(g);
            int w = getWidth();
            int h = getHeight();
            Color color = Main.modalityColor(modality);
            Main.drawIcon(g2, Main.modalityIcon(modality), 0, (h - 18) / 2, 18, color);
            g2.setFont(Main.font(Font.BOLD, 13.5f));
            g2.setColor(Main.TEXT);
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(PhishingDetector.displayName(modality), 28, (h - fm.getHeight()) / 2 + fm.getAscent());

            int barX = 90;
            int barW = Math.max(40, w - barX - 50);
            int barY = h / 2 - 5;
            g2.setColor(new Color(33, 46, 75));
            g2.fill(new RoundRectangle2D.Double(barX, barY, barW, 10, 10, 10));

            g2.setFont(Main.font(Font.BOLD, 14));
            fm = g2.getFontMetrics();
            if (score < 0) {
                g2.setFont(Main.font(Font.ITALIC, 12));
                g2.setColor(Main.TEXT_DIM);
                FontMetrics small = g2.getFontMetrics();
                g2.drawString("not scanned yet", barX + 10, (h - small.getHeight()) / 2 + small.getAscent());
                g2.setFont(Main.font(Font.BOLD, 14));
                g2.drawString("--", w - fm.stringWidth("--"), (h - fm.getHeight()) / 2 + fm.getAscent());
            } else {
                Color risk = Main.riskColor(score);
                int fill = Math.max(10, (int) (barW * score / 100.0));
                g2.setPaint(new GradientPaint(barX, 0, Main.withAlpha(risk, 140), barX + fill, 0, risk));
                g2.fill(new RoundRectangle2D.Double(barX, barY, fill, 10, 10, 10));
                g2.setColor(risk);
                String text = String.valueOf(score);
                g2.drawString(text, w - fm.stringWidth(text), (h - fm.getHeight()) / 2 + fm.getAscent());
            }
            g2.dispose();
        }
    }

    /** Donut chart of HIGH / SUSPICIOUS / LOW scans with a legend. */
    private static class DonutChart extends JComponent {
        private int high;
        private int suspicious;
        private int low;

        DonutChart() {
            setPreferredSize(new Dimension(280, 220));
        }

        void setValues(int high, int suspicious, int low) {
            this.high = high;
            this.suspicious = suspicious;
            this.low = low;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Main.smooth(g);
            int w = getWidth();
            int h = getHeight();
            int total = high + suspicious + low;

            int size = Math.min(Math.min(h - 10, (int) (w * 0.52)), 200);
            float stroke = size * 0.16f;
            double x = stroke / 2 + 2;
            double y = (h - size) / 2.0 + stroke / 2;
            double d = size - stroke;

            g2.setStroke(new BasicStroke(stroke, BasicStroke.CAP_BUTT, BasicStroke.JOIN_ROUND));
            g2.setColor(new Color(33, 46, 75));
            g2.draw(new Ellipse2D.Double(x, y, d, d));

            int[] values = {high, suspicious, low};
            Color[] colors = {Main.RED, Main.ORANGE, Main.GREEN};
            String[] names = {"High risk", "Suspicious", "Low risk"};
            if (total > 0) {
                double start = 90;
                for (int i = 0; i < values.length; i++) {
                    if (values[i] == 0) {
                        continue;
                    }
                    double extent = 360.0 * values[i] / total;
                    double gap = values[i] == total ? 0 : Math.min(3, extent / 3);
                    g2.setColor(colors[i]);
                    g2.draw(new Arc2D.Double(x, y, d, d, start - gap / 2, -(extent - gap), Arc2D.OPEN));
                    start -= extent;
                }
            }

            // center text
            double cx = x + d / 2;
            double cy = y + d / 2;
            g2.setFont(Main.font(Font.BOLD, size * 0.2f));
            FontMetrics fm = g2.getFontMetrics();
            String number = String.valueOf(total);
            g2.setColor(Main.TEXT);
            g2.drawString(number, (int) (cx - fm.stringWidth(number) / 2.0), (int) (cy + fm.getAscent() * 0.25));
            g2.setFont(Main.font(Font.PLAIN, 12));
            FontMetrics small = g2.getFontMetrics();
            String caption = total == 1 ? "scan" : "scans";
            g2.setColor(Main.TEXT_MUTED);
            g2.drawString(caption, (int) (cx - small.stringWidth(caption) / 2.0), (int) (cy + fm.getAscent() * 0.25) + small.getHeight() + 2);

            // legend
            int legendX = size + 26;
            int legendY = (h - 3 * 50) / 2;
            for (int i = 0; i < values.length; i++) {
                int rowY = legendY + i * 50;
                g2.setColor(colors[i]);
                g2.fill(new RoundRectangle2D.Double(legendX, rowY + 4, 10, 10, 4, 4));
                g2.setFont(Main.font(Font.BOLD, 13));
                g2.setColor(Main.TEXT);
                g2.drawString(names[i], legendX + 20, rowY + 14);
                g2.setFont(Main.font(Font.PLAIN, 12));
                g2.setColor(Main.TEXT_MUTED);
                g2.drawString(values[i] + (values[i] == 1 ? " scan" : " scans") + "  |  " + percent(values[i], total),
                        legendX + 20, rowY + 33);
            }
            g2.dispose();
        }
    }

    /** Vertical bar chart of scans per type. */
    private static class BarChart extends JComponent {
        private static final String[] LABELS = {"Email", "Image", "Voice", "Multi"};
        private static final String[] TYPES = {
                PhishingDetector.EMAIL, PhishingDetector.IMAGE, PhishingDetector.VOICE, PhishingDetector.MULTIMODAL};
        private int[] values = new int[4];

        BarChart() {
            setPreferredSize(new Dimension(280, 230));
        }

        void setValues(int[] values) {
            this.values = values.clone();
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Main.smooth(g);
            int w = getWidth();
            int h = getHeight();
            int left = 30;
            int bottom = 30;
            int top = 22;
            int chartH = h - top - bottom;
            int chartW = w - left;

            int max = 1;
            for (int v : values) {
                max = Math.max(max, v);
            }
            int niceMax = max <= 4 ? 4 : (int) (Math.ceil(max / 4.0) * 4);

            // grid lines with numbers
            g2.setFont(Main.font(Font.PLAIN, 11));
            FontMetrics fm = g2.getFontMetrics();
            g2.setStroke(new BasicStroke(1f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10f, new float[]{4f, 4f}, 0f));
            for (int i = 0; i <= 4; i++) {
                int y = top + chartH - chartH * i / 4;
                g2.setColor(new Color(36, 50, 80, 160));
                g2.draw(new Line2D.Double(left, y, w, y));
                String label = String.valueOf(niceMax * i / 4);
                g2.setColor(Main.TEXT_DIM);
                g2.drawString(label, left - 10 - fm.stringWidth(label), y + fm.getAscent() / 2 - 1);
            }

            int slot = chartW / values.length;
            int barW = Math.min(46, (int) (slot * 0.5));
            for (int i = 0; i < values.length; i++) {
                Color color = Main.modalityColor(TYPES[i]);
                int barH = (int) (chartH * (values[i] / (double) niceMax));
                int x = left + slot * i + (slot - barW) / 2;
                int y = top + chartH - barH;
                if (barH > 0) {
                    // rounded top, flat bottom: draw a taller rounded bar and cut off the bottom with a clip
                    java.awt.Shape oldClip = g2.getClip();
                    g2.clipRect(x, y, barW, barH);
                    g2.setPaint(new GradientPaint(0, y, color, 0, y + barH, Main.withAlpha(color, 60)));
                    g2.fill(new RoundRectangle2D.Double(x, y, barW, barH + 10, 10, 10));
                    g2.setClip(oldClip);
                }
                g2.setFont(Main.font(Font.BOLD, 13));
                FontMetrics valueFm = g2.getFontMetrics();
                String value = String.valueOf(values[i]);
                g2.setColor(Main.TEXT);
                g2.drawString(value, x + (barW - valueFm.stringWidth(value)) / 2, y - 7);

                g2.setFont(Main.font(Font.PLAIN, 12));
                FontMetrics labelFm = g2.getFontMetrics();
                g2.setColor(Main.TEXT_MUTED);
                g2.drawString(LABELS[i], x + (barW - labelFm.stringWidth(LABELS[i])) / 2, h - 8);
            }
            g2.dispose();
        }
    }
}
