import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.RowFilter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.geom.RoundRectangle2D;
import java.util.List;
import java.util.regex.Pattern;

/**
 * HistoryPanel - shows every saved scan from scan_history.csv in a styled JTable.
 * The user can search, refresh and clear the history.
 */
public class HistoryPanel extends JPanel {

    private static final String[] COLUMNS = {"Date & Time", "Scan Type", "Risk Score", "Classification", "Summary"};
    private static final Color ROW_EVEN = Main.BG_CARD;
    private static final Color ROW_ODD = new Color(20, 30, 52);
    private static final Color ROW_SELECTED = new Color(24, 56, 84);

    private final Main app;
    private final DefaultTableModel model;
    private final JTable table;
    private final TableRowSorter<DefaultTableModel> sorter;
    private final Main.HintTextField searchField = new Main.HintTextField("Search by type, classification, sender or keyword...", "scan");
    private final JLabel countLabel = Main.createLabel("", Main.font(Font.PLAIN, 12.5f), Main.TEXT_MUTED);
    private final JLabel pathLabel = Main.createLabel("", Main.font(Font.PLAIN, 12), Main.TEXT_DIM);

    public HistoryPanel(Main app) {
        this.app = app;

        // ---- table model: read-only, score column sorts as a number ----
        model = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int column) {
                return column == 2 ? Integer.class : String.class;
            }
        };
        table = new JTable(model);
        sorter = new TableRowSorter<>(model);
        table.setRowSorter(sorter);
        styleTable();

        // ---- toolbar ----
        Main.ModernButton refreshButton = new Main.ModernButton("Refresh", "refresh", Main.ModernButton.Style.SECONDARY);
        Main.ModernButton clearButton = new Main.ModernButton("Clear History", "trash", Main.ModernButton.Style.DANGER);
        refreshButton.addActionListener(e -> refresh());
        clearButton.addActionListener(e -> clearHistory());
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                applySearch();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                applySearch();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                applySearch();
            }
        });

        JPanel toolbar = new JPanel(new BorderLayout(14, 0));
        toolbar.setOpaque(false);
        searchField.setPreferredSize(new Dimension(380, 44));
        toolbar.add(searchField, BorderLayout.CENTER);
        toolbar.add(Main.createButtonRow(refreshButton, clearButton), BorderLayout.EAST);

        // ---- table card ----
        JScrollPane scroll = Main.createScrollPane(table, Main.BG_CARD);
        JPanel corner = new JPanel();
        corner.setBackground(Main.BG_INPUT);
        scroll.setCorner(JScrollPane.UPPER_RIGHT_CORNER, corner);
        scroll.getViewport().setBackground(Main.BG_CARD);

        Main.RoundedPanel tableBox = new Main.RoundedPanel(new BorderLayout(), 16, Main.BG_CARD, Main.BORDER);
        tableBox.setBorder(new EmptyBorder(1, 1, 8, 1));
        tableBox.add(scroll);

        JPanel footer = new JPanel(new BorderLayout());
        footer.setOpaque(false);
        footer.add(countLabel, BorderLayout.WEST);
        footer.add(pathLabel, BorderLayout.EAST);

        Main.RoundedPanel card = new Main.RoundedPanel(new BorderLayout(0, 16));
        card.setBorder(new EmptyBorder(22, 22, 18, 22));
        card.add(toolbar, BorderLayout.NORTH);
        card.add(tableBox, BorderLayout.CENTER);
        card.add(footer, BorderLayout.SOUTH);

        Main.setupPage(this,
                Main.createPageHeader("Scan History",
                        "Every scan is saved to a CSV file. Search, sort by clicking a column, or clear the history.", "history"),
                card);
        refresh();
    }

    /** Reloads the table from the CSV file (newest scan first). */
    public void refresh() {
        model.setRowCount(0);
        List<HistoryManager.ScanRecord> records = app.getHistoryManager().loadNewestFirst();
        for (HistoryManager.ScanRecord record : records) {
            model.addRow(new Object[]{record.dateTime, record.scanType, record.riskScore, record.classification, record.summary});
        }
        pathLabel.setText("File: " + app.getHistoryManager().getFilePath());
        updateCount();
    }

    private void applySearch() {
        String text = searchField.getText().trim();
        if (text.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            // (?i) = ignore upper/lower case; Pattern.quote = treat the text literally
            sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
        }
        updateCount();
    }

    private void updateCount() {
        int shown = table.getRowCount();
        int total = model.getRowCount();
        countLabel.setText(total == 0 ? "No scans saved yet - run a scan to see it here."
                : "Showing " + shown + " of " + total + " scans");
    }

    private void clearHistory() {
        if (model.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this, "The history is already empty.", "Scan history", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        int answer = JOptionPane.showConfirmDialog(this,
                "Delete all " + model.getRowCount() + " saved scans?\nThis cannot be undone.",
                "Clear history", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (answer == JOptionPane.YES_OPTION) {
            if (!app.getHistoryManager().clearHistory()) {
                JOptionPane.showMessageDialog(this, "The history file could not be cleared.", "Error", JOptionPane.ERROR_MESSAGE);
            }
            app.refreshAll();
        }
    }

    // =====================================================================
    // Table styling
    // =====================================================================

    private void styleTable() {
        table.setRowHeight(48);
        table.setShowVerticalLines(false);
        table.setShowHorizontalLines(true);
        table.setGridColor(new Color(30, 42, 68));
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setBackground(Main.BG_CARD);
        table.setForeground(Main.TEXT);
        table.setSelectionBackground(ROW_SELECTED);
        table.setSelectionForeground(Color.WHITE);
        table.setFont(Main.font(Font.PLAIN, 13));
        table.setFillsViewportHeight(true);
        table.setFocusable(false);

        JTableHeader header = table.getTableHeader();
        header.setReorderingAllowed(false);
        header.setPreferredSize(new Dimension(0, 44));
        header.setBackground(Main.BG_INPUT);
        header.setDefaultRenderer(new HeaderRenderer());

        TextRenderer textRenderer = new TextRenderer();
        table.setDefaultRenderer(String.class, textRenderer);
        TableColumnModel columns = table.getColumnModel();
        columns.getColumn(0).setCellRenderer(textRenderer);
        columns.getColumn(1).setCellRenderer(new PillRenderer(true));
        columns.getColumn(2).setCellRenderer(new ScoreRenderer());
        columns.getColumn(3).setCellRenderer(new PillRenderer(false));
        columns.getColumn(4).setCellRenderer(textRenderer);

        int[] widths = {165, 140, 170, 150, 520};
        for (int i = 0; i < widths.length; i++) {
            columns.getColumn(i).setPreferredWidth(widths[i]);
        }
        columns.getColumn(0).setMinWidth(150);
        columns.getColumn(1).setMinWidth(120);
        columns.getColumn(2).setMinWidth(140);
        columns.getColumn(3).setMinWidth(135);
    }

    private static Color rowColor(JTable table, int row, boolean selected) {
        if (selected) {
            return ROW_SELECTED;
        }
        return row % 2 == 0 ? ROW_EVEN : ROW_ODD;
    }

    /** Dark header with small uppercase titles. */
    private static class HeaderRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, false, false, row, column);
            label.setText(String.valueOf(value).toUpperCase());
            label.setFont(Main.tracked(Main.font(Font.BOLD, 11), 0.08f));
            label.setForeground(Main.TEXT_MUTED);
            label.setBackground(Main.BG_INPUT);
            label.setOpaque(true);
            label.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 1, 0, Main.BORDER),
                    new EmptyBorder(0, 16, 0, 16)));
            return label;
        }
    }

    /** Normal text cells (date and summary). */
    private static class TextRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, false, row, column);
            label.setBackground(rowColor(table, row, isSelected));
            label.setBorder(new EmptyBorder(0, 16, 0, 16));
            int modelColumn = table.convertColumnIndexToModel(column);
            if (modelColumn == 4) {
                label.setForeground(isSelected ? Color.WHITE : new Color(196, 206, 226));
                label.setToolTipText(String.valueOf(value));
                label.setFont(Main.font(Font.PLAIN, 13));
            } else {
                label.setForeground(isSelected ? Color.WHITE : Main.TEXT_MUTED);
                label.setToolTipText(null);
                label.setFont(Main.font(Font.PLAIN, 12.5f));
            }
            return label;
        }
    }

    /** Draws the scan type or classification as a colored pill. */
    private static class PillRenderer extends JComponent implements TableCellRenderer {
        private final boolean isTypeColumn;
        private String text = "";
        private Color color = Main.TEXT_MUTED;
        private Color background = ROW_EVEN;
        private String iconName;

        PillRenderer(boolean isTypeColumn) {
            this.isTypeColumn = isTypeColumn;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            String raw = String.valueOf(value);
            if (isTypeColumn) {
                text = PhishingDetector.displayName(raw);
                color = Main.modalityColor(raw);
                iconName = Main.modalityIcon(raw);
            } else {
                text = raw;
                color = Main.classificationColor(raw);
                iconName = null;
            }
            background = rowColor(table, row, isSelected);
            return this;
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Main.smooth(g);
            g2.setColor(background);
            g2.fillRect(0, 0, getWidth(), getHeight());
            g2.setFont(isTypeColumn ? Main.font(Font.BOLD, 12.5f) : Main.tracked(Main.font(Font.BOLD, 11.5f), 0.05f));
            FontMetrics fm = g2.getFontMetrics();
            int padLeft = iconName != null ? 32 : 24;
            int pillW = fm.stringWidth(text) + padLeft + 12;
            int pillH = 26;
            int x = 16;
            int y = (getHeight() - pillH) / 2;
            RoundRectangle2D pill = new RoundRectangle2D.Double(x, y, pillW, pillH, pillH, pillH);
            g2.setColor(Main.withAlpha(color, 34));
            g2.fill(pill);
            g2.setColor(Main.withAlpha(color, 110));
            g2.draw(pill);
            if (iconName != null) {
                Main.drawIcon(g2, iconName, x + 10, y + 5, 16, color);
            } else {
                g2.setColor(color);
                g2.fillOval(x + 10, y + pillH / 2 - 3, 6, 6);
            }
            g2.setColor(color);
            g2.drawString(text, x + padLeft, y + (pillH - fm.getHeight()) / 2 + fm.getAscent());
            g2.dispose();
        }
    }

    /** Shows the score as a number plus a small progress bar. */
    private static class ScoreRenderer extends JComponent implements TableCellRenderer {
        private int score;
        private Color background = ROW_EVEN;

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            score = value instanceof Integer ? (Integer) value : 0;
            background = rowColor(table, row, isSelected);
            return this;
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = Main.smooth(g);
            g2.setColor(background);
            g2.fillRect(0, 0, getWidth(), getHeight());
            Color color = Main.riskColor(score);
            g2.setFont(Main.font(Font.BOLD, 14));
            FontMetrics fm = g2.getFontMetrics();
            String text = String.valueOf(score);
            int x = 16;
            g2.setColor(color);
            g2.drawString(text, x, (getHeight() - fm.getHeight()) / 2 + fm.getAscent());

            int barX = x + 34;
            int barW = Math.max(30, Math.min(90, getWidth() - barX - 16));
            int barY = getHeight() / 2 - 3;
            g2.setColor(new Color(33, 46, 75));
            g2.fill(new RoundRectangle2D.Double(barX, barY, barW, 6, 6, 6));
            g2.setColor(color);
            g2.fill(new RoundRectangle2D.Double(barX, barY, Math.max(6, barW * score / 100.0), 6, 6, 6));
            g2.dispose();
        }
    }
}
