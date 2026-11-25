import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.Scrollable;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.basic.BasicScrollBarUI;
import java.awt.AlphaComposite;
import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.LayoutManager;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.event.ActionEvent;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.font.TextAttribute;
import java.awt.geom.AffineTransform;
import java.awt.geom.Arc2D;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Main - starts the application and builds the main window.
 *
 * The window has two parts:
 *   LEFT  : a sidebar with the logo and navigation buttons
 *   RIGHT : a content area that uses CardLayout to switch between pages
 *
 * This file also contains the shared THEME (colors and fonts) and a few
 * small reusable widgets (rounded panels, modern buttons, text fields ...)
 * so that every page of the app looks the same.
 */
public class Main extends JFrame {

    // =====================================================================
    // THEME - all colors used by the application
    // =====================================================================
    public static final Color BG_APP = new Color(10, 16, 31);       // window background (dark navy)
    public static final Color BG_SIDEBAR = new Color(7, 12, 24);
    public static final Color BG_CARD = new Color(17, 26, 46);      // panels and cards
    public static final Color BG_CARD_ALT = new Color(23, 34, 59);
    public static final Color BG_INPUT = new Color(12, 20, 37);     // text fields
    public static final Color BORDER = new Color(36, 50, 80);
    public static final Color CYAN = new Color(34, 211, 238);       // main accent
    public static final Color BLUE = new Color(59, 130, 246);       // second accent
    public static final Color PURPLE = new Color(167, 139, 250);
    public static final Color TEXT = new Color(232, 238, 252);      // main text (white)
    public static final Color TEXT_MUTED = new Color(138, 152, 180);
    public static final Color TEXT_DIM = new Color(92, 106, 136);
    public static final Color RED = new Color(248, 81, 73);         // high risk
    public static final Color ORANGE = new Color(251, 146, 60);     // suspicious
    public static final Color GREEN = new Color(52, 211, 153);      // safe

    // Page names used by the CardLayout
    public static final String PAGE_DASHBOARD = "Dashboard";
    public static final String PAGE_EMAIL = "Email Scanner";
    public static final String PAGE_IMAGE = "Image Scanner";
    public static final String PAGE_VOICE = "Voice Scam Report";
    public static final String PAGE_HISTORY = "Scan History";

    private static String fontFamily;

    // =====================================================================
    // APPLICATION STATE
    // =====================================================================
    private final HistoryManager historyManager = new HistoryManager("scan_history.csv");
    /** Latest result of each modality in this session - used by the multimodal analysis. */
    private final Map<String, PhishingDetector.Result> latestResults = new LinkedHashMap<>();

    private final CardLayout cardLayout = new CardLayout();
    private final JPanel contentArea = new JPanel(cardLayout);
    private final Map<String, NavButton> navButtons = new LinkedHashMap<>();
    private final DashboardPanel dashboardPanel;
    private final HistoryPanel historyPanel;

    // =====================================================================
    // PROGRAM START
    // =====================================================================
    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "on"); // smooth text on Linux
        SwingUtilities.invokeLater(() -> {
            applyGlobalStyle();
            new Main().setVisible(true);
        });
    }

    public Main() {
        super("Multimodal Phishing Detection - Email, Image and Voice");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1320, 860);
        setMinimumSize(new Dimension(1120, 720));
        setLocationRelativeTo(null);
        setIconImages(List.of(createAppIcon(16), createAppIcon(32), createAppIcon(64)));

        dashboardPanel = new DashboardPanel(this);
        historyPanel = new HistoryPanel(this);

        contentArea.setBackground(BG_APP);
        contentArea.add(dashboardPanel, PAGE_DASHBOARD);
        contentArea.add(new EmailScannerPanel(this), PAGE_EMAIL);
        contentArea.add(new ImageScannerPanel(this), PAGE_IMAGE);
        contentArea.add(new VoiceScannerPanel(this), PAGE_VOICE);
        contentArea.add(historyPanel, PAGE_HISTORY);

        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(BG_APP);
        root.add(createSidebar(), BorderLayout.WEST);
        root.add(contentArea, BorderLayout.CENTER);
        setContentPane(root);

        showPage(PAGE_DASHBOARD);
    }

    // =====================================================================
    // METHODS USED BY THE PAGES
    // =====================================================================

    /** Switches the content area to another page and highlights its sidebar button. */
    public void showPage(String page) {
        if (page.equals(PAGE_DASHBOARD)) {
            dashboardPanel.refresh();
        } else if (page.equals(PAGE_HISTORY)) {
            historyPanel.refresh();
        }
        cardLayout.show(contentArea, page);
        for (Map.Entry<String, NavButton> entry : navButtons.entrySet()) {
            entry.getValue().setSelected(entry.getKey().equals(page));
        }
    }

    public HistoryManager getHistoryManager() {
        return historyManager;
    }

    /** Latest Email, Image and Voice results of this session (in that order). */
    public List<PhishingDetector.Result> getLatestResults() {
        List<PhishingDetector.Result> list = new ArrayList<>();
        for (String modality : new String[]{PhishingDetector.EMAIL, PhishingDetector.IMAGE, PhishingDetector.VOICE}) {
            if (latestResults.containsKey(modality)) {
                list.add(latestResults.get(modality));
            }
        }
        return list;
    }

    public PhishingDetector.Result getLatestResult(String modality) {
        return latestResults.get(modality);
    }

    /** Called by every scanner page after a scan: remember it, save it, refresh the screens. */
    public void onScanCompleted(PhishingDetector.Result result) {
        latestResults.put(result.modality, result);
        saveToHistory(result);
    }

    /** Saves a result (single or multimodal) to the CSV history file. */
    public void saveToHistory(PhishingDetector.Result result) {
        boolean saved = historyManager.addRecord(result.modality, result.score, result.classification, result.summary);
        if (!saved) {
            JOptionPane.showMessageDialog(this, "The scan could not be saved to " + historyManager.getFilePath(),
                    "History error", JOptionPane.ERROR_MESSAGE);
        }
        refreshAll();
    }

    /** Forgets the latest results used by the multimodal analysis (history is kept). */
    public void resetSession() {
        latestResults.clear();
        refreshAll();
    }

    public void refreshAll() {
        dashboardPanel.refresh();
        historyPanel.refresh();
    }

    // =====================================================================
    // SIDEBAR
    // =====================================================================
    private JPanel createSidebar() {
        JPanel sidebar = new JPanel(new BorderLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                g.setColor(BG_SIDEBAR);
                g.fillRect(0, 0, getWidth(), getHeight());
                g.setColor(BORDER);
                g.drawLine(getWidth() - 1, 0, getWidth() - 1, getHeight());
            }
        };
        sidebar.setPreferredSize(new Dimension(252, 0));

        // ---- Logo area ----
        JPanel logo = new JPanel(new BorderLayout(12, 0));
        logo.setOpaque(false);
        logo.setBorder(new EmptyBorder(26, 22, 26, 18));
        logo.add(new LogoMark(44), BorderLayout.WEST);
        JPanel logoText = new JPanel(new GridLayout(2, 1, 0, 0));
        logoText.setOpaque(false);
        logoText.add(createLabel("PhishGuard", font(Font.BOLD, 20), TEXT));
        logoText.add(createLabel("Multimodal Detection", font(Font.PLAIN, 12), TEXT_MUTED));
        logo.add(logoText, BorderLayout.CENTER);

        // ---- Navigation ----
        JPanel nav = new JPanel();
        nav.setOpaque(false);
        nav.setLayout(new BoxLayout(nav, BoxLayout.Y_AXIS));
        nav.setBorder(new EmptyBorder(4, 0, 0, 0));
        nav.add(createSidebarCaption("MAIN MENU"));
        addNavButton(nav, PAGE_DASHBOARD, "dashboard");
        nav.add(Box.createVerticalStrut(14));
        nav.add(createSidebarCaption("SCANNERS"));
        addNavButton(nav, PAGE_EMAIL, "email");
        addNavButton(nav, PAGE_IMAGE, "image");
        addNavButton(nav, PAGE_VOICE, "voice");
        nav.add(Box.createVerticalStrut(14));
        nav.add(createSidebarCaption("RECORDS"));
        addNavButton(nav, PAGE_HISTORY, "history");

        // ---- Footer ----
        RoundedPanel footer = new RoundedPanel(new BorderLayout(10, 0), 14, BG_CARD, BORDER);
        footer.setBorder(new EmptyBorder(12, 14, 12, 14));
        JLabel footerIcon = new JLabel(icon("shield", 20, CYAN));
        JPanel footerText = new JPanel(new GridLayout(2, 1));
        footerText.setOpaque(false);
        footerText.add(createLabel("Phishing Detection System", font(Font.BOLD, 12), TEXT));
        footerText.add(createLabel("v1.0  |  Offline rule engine", font(Font.PLAIN, 11), TEXT_MUTED));
        footer.add(footerIcon, BorderLayout.WEST);
        footer.add(footerText, BorderLayout.CENTER);
        JPanel footerWrap = new JPanel(new BorderLayout());
        footerWrap.setOpaque(false);
        footerWrap.setBorder(new EmptyBorder(0, 16, 20, 16));
        footerWrap.add(footer);

        sidebar.add(logo, BorderLayout.NORTH);
        sidebar.add(nav, BorderLayout.CENTER);
        sidebar.add(footerWrap, BorderLayout.SOUTH);
        return sidebar;
    }

    private void addNavButton(JPanel nav, String page, String iconName) {
        NavButton button = new NavButton(page, iconName, () -> showPage(page));
        navButtons.put(page, button);
        nav.add(button);
        nav.add(Box.createVerticalStrut(4));
    }

    private JComponent createSidebarCaption(String text) {
        JLabel label = createLabel(text, tracked(font(Font.BOLD, 10.5f), 0.12f), TEXT_DIM);
        label.setBorder(new EmptyBorder(6, 26, 8, 0));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        return label;
    }

    /** Global defaults so that message dialogs also use the dark theme. */
    private static void applyGlobalStyle() {
        UIManager.put("OptionPane.background", BG_CARD);
        UIManager.put("Panel.background", BG_CARD);
        UIManager.put("OptionPane.messageForeground", TEXT);
        UIManager.put("OptionPane.messageFont", font(Font.PLAIN, 14));
        UIManager.put("OptionPane.buttonFont", font(Font.BOLD, 13));
        UIManager.put("Button.background", BLUE);
        UIManager.put("Button.foreground", Color.WHITE);
        UIManager.put("Button.select", BLUE.darker());
        UIManager.put("Button.focus", new Color(0, 0, 0, 0));
        UIManager.put("ToolTip.background", BG_CARD_ALT);
        UIManager.put("ToolTip.foreground", TEXT);
        UIManager.put("ToolTip.font", font(Font.PLAIN, 12));
        UIManager.put("ToolTip.border", BorderFactory.createLineBorder(BORDER));
    }

    // =====================================================================
    // SHARED HELPERS (fonts, colors, labels, layout pieces)
    // =====================================================================

    /** Returns a modern font. Uses Segoe UI on Windows and falls back to the default font elsewhere. */
    public static Font font(int style, float size) {
        if (fontFamily == null) {
            fontFamily = Font.SANS_SERIF;
            List<String> available = Arrays.asList(
                    GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames());
            for (String name : new String[]{"Segoe UI", "Inter", "Helvetica Neue", "Roboto", "Ubuntu", "DejaVu Sans"}) {
                if (available.contains(name)) {
                    fontFamily = name;
                    break;
                }
            }
        }
        return new Font(fontFamily, style, 12).deriveFont(size);
    }

    /** Adds letter spacing to a font (nice for small uppercase captions). */
    public static Font tracked(Font base, float tracking) {
        return base.deriveFont(Collections.singletonMap(TextAttribute.TRACKING, tracking));
    }

    /** Green / orange / red depending on the score. */
    public static Color riskColor(int score) {
        if (score >= 60) {
            return RED;
        }
        if (score >= 30) {
            return ORANGE;
        }
        return GREEN;
    }

    public static Color classificationColor(String classification) {
        if (PhishingDetector.HIGH_RISK.equals(classification)) {
            return RED;
        }
        if (PhishingDetector.SUSPICIOUS.equals(classification)) {
            return ORANGE;
        }
        return GREEN;
    }

    public static Color modalityColor(String modality) {
        switch (modality) {
            case PhishingDetector.EMAIL:
                return BLUE;
            case PhishingDetector.IMAGE:
                return PURPLE;
            case PhishingDetector.VOICE:
                return CYAN;
            default:
                return new Color(244, 114, 182); // pink for multimodal
        }
    }

    public static String modalityIcon(String modality) {
        switch (modality) {
            case PhishingDetector.EMAIL:
                return "email";
            case PhishingDetector.IMAGE:
                return "image";
            case PhishingDetector.VOICE:
                return "voice";
            default:
                return "layers";
        }
    }

    public static Color withAlpha(Color color, int alpha) {
        return new Color(color.getRed(), color.getGreen(), color.getBlue(), Math.max(0, Math.min(255, alpha)));
    }

    /** Creates a Graphics2D copy with anti-aliasing switched on (smooth edges). */
    public static Graphics2D smooth(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        g2.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        return g2;
    }

    public static JLabel createLabel(String text, Font font, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(font);
        label.setForeground(color);
        return label;
    }

    /** Small uppercase label shown above an input field. */
    public static JLabel createFieldLabel(String text) {
        JLabel label = createLabel(text.toUpperCase(), tracked(font(Font.BOLD, 11), 0.08f), TEXT_MUTED);
        label.setBorder(new EmptyBorder(0, 2, 7, 0));
        return label;
    }

    /** Big page title with an icon badge, a subtitle and an "offline" status chip. */
    public static JPanel createPageHeader(String title, String subtitle, String iconName) {
        JPanel header = new JPanel(new BorderLayout(16, 0));
        header.setOpaque(false);
        header.add(new IconBadge(iconName, 52, CYAN), BorderLayout.WEST);

        JPanel texts = new JPanel(new GridLayout(2, 1, 0, 2));
        texts.setOpaque(false);
        texts.add(createLabel(title, font(Font.BOLD, 26), TEXT));
        texts.add(createLabel(subtitle, font(Font.PLAIN, 14), TEXT_MUTED));
        header.add(texts, BorderLayout.CENTER);

        JPanel chipWrap = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 12));
        chipWrap.setOpaque(false);
        chipWrap.add(new Pill("OFFLINE ANALYSIS", GREEN));
        header.add(chipWrap, BorderLayout.EAST);
        return header;
    }

    /** Icon + bold title used at the top of each card. */
    public static JLabel createCardTitle(String title, String iconName) {
        JLabel label = createLabel(title, font(Font.BOLD, 16), TEXT);
        label.setIcon(icon(iconName, 18, CYAN));
        label.setIconTextGap(10);
        return label;
    }

    /** The right-hand card of every scanner page that holds a ResultPanel. */
    public static JComponent createResultCard(ResultPanel resultPanel) {
        RoundedPanel card = new RoundedPanel(new BorderLayout(0, 14), 20, BG_CARD, BORDER);
        card.setBorder(new EmptyBorder(22, 22, 14, 14));
        JLabel title = createCardTitle("Analysis Result", "shield");
        title.setBorder(new EmptyBorder(0, 0, 0, 8));
        card.add(title, BorderLayout.NORTH);
        card.add(resultPanel, BorderLayout.CENTER);
        return card;
    }

    /** Two equal columns: input card on the left, result card on the right. */
    public static JPanel createTwoColumnBody(JComponent left, JComponent right) {
        JPanel body = new JPanel(new GridLayout(1, 2, 22, 0));
        body.setOpaque(false);
        body.add(left);
        body.add(right);
        return body;
    }

    /** Standard page container: dark background, padding, header on top. */
    public static void setupPage(JPanel page, JComponent header, JComponent body) {
        page.setLayout(new BorderLayout(0, 22));
        page.setBackground(BG_APP);
        page.setBorder(new EmptyBorder(28, 32, 28, 32));
        page.add(header, BorderLayout.NORTH);
        page.add(body, BorderLayout.CENTER);
    }

    /** A row of buttons with 10px gaps. */
    public static JPanel createButtonRow(JComponent... buttons) {
        JPanel row = new JPanel();
        row.setOpaque(false);
        row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
        for (int i = 0; i < buttons.length; i++) {
            if (i > 0) {
                row.add(Box.createHorizontalStrut(10));
            }
            row.add(buttons[i]);
        }
        row.add(Box.createHorizontalGlue());
        return row;
    }

    /** Multi-line text input with a placeholder hint. */
    public static JTextArea createTextArea(String hint) {
        HintTextArea area = new HintTextArea(hint);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(font(Font.PLAIN, 14));
        area.setForeground(TEXT);
        area.setBackground(BG_INPUT);
        area.setCaretColor(CYAN);
        area.setSelectionColor(withAlpha(CYAN, 90));
        area.setSelectedTextColor(Color.WHITE);
        area.setBorder(new EmptyBorder(4, 4, 4, 4));
        area.setTabSize(4);
        return area;
    }

    /** Puts a text area inside a rounded box with a scrollbar; the border glows when focused. */
    public static JComponent wrapTextArea(JTextArea area) {
        RoundedPanel box = new RoundedPanel(new BorderLayout(), 14, BG_INPUT, BORDER);
        box.setBorder(new EmptyBorder(8, 10, 8, 4));
        JScrollPane scroll = createScrollPane(area, BG_INPUT);
        box.add(scroll);
        area.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                box.setBorderColor(withAlpha(CYAN, 170));
            }

            @Override
            public void focusLost(FocusEvent e) {
                box.setBorderColor(BORDER);
            }
        });
        box.setPreferredSize(new Dimension(200, 120));
        return box;
    }

    /** A scroll pane with thin modern scrollbars. Pass null as background for a transparent one. */
    public static JScrollPane createScrollPane(Component view, Color background) {
        JScrollPane scroll = new JScrollPane(view);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.setViewportBorder(null);
        boolean opaque = background != null;
        scroll.setOpaque(opaque);
        scroll.getViewport().setOpaque(opaque);
        if (opaque) {
            scroll.setBackground(background);
            scroll.getViewport().setBackground(background);
        }
        for (JScrollBar bar : new JScrollBar[]{scroll.getVerticalScrollBar(), scroll.getHorizontalScrollBar()}) {
            bar.setUI(new ModernScrollBarUI());
            bar.setOpaque(false);
            bar.setUnitIncrement(18);
        }
        scroll.getVerticalScrollBar().setPreferredSize(new Dimension(10, 0));
        scroll.getHorizontalScrollBar().setPreferredSize(new Dimension(0, 10));
        return scroll;
    }

    /** Lets the user press Ctrl+Enter inside a text field to run the scan. */
    public static void bindCtrlEnter(JComponent component, Runnable action) {
        component.getInputMap().put(KeyStroke.getKeyStroke("control ENTER"), "run-scan");
        component.getActionMap().put("run-scan", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    public static void showWarning(Component parent, String message) {
        JOptionPane.showMessageDialog(parent, message, "Missing information", JOptionPane.WARNING_MESSAGE);
    }

    /** Wraps drawIcon() so an icon can be used on a JLabel. */
    public static Icon icon(String name, int size, Color color) {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                drawIcon((Graphics2D) g, name, x, y, size, color);
            }

            @Override
            public int getIconWidth() {
                return size;
            }

            @Override
            public int getIconHeight() {
                return size;
            }
        };
    }

    /** A small colored dot icon (used in legends and lists). */
    public static Icon dotIcon(Color color, int size) {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = smooth(g);
                g2.setColor(color);
                g2.fillOval(x, y, size, size);
                g2.dispose();
            }

            @Override
            public int getIconWidth() {
                return size;
            }

            @Override
            public int getIconHeight() {
                return size;
            }
        };
    }

    /**
     * Draws simple line icons with Java 2D (no image files needed).
     * Every icon is designed on a 24 x 24 grid and scaled to the wanted size.
     */
    public static void drawIcon(Graphics2D g, String name, int x, int y, int size, Color color) {
        Graphics2D g2 = smooth(g);
        g2.translate(x, y);
        g2.scale(size / 24.0, size / 24.0);
        g2.setColor(color);
        g2.setStroke(new BasicStroke(2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));

        switch (name) {
            case "dashboard":
                g2.draw(new RoundRectangle2D.Double(3, 3, 7, 7, 3, 3));
                g2.draw(new RoundRectangle2D.Double(14, 3, 7, 7, 3, 3));
                g2.draw(new RoundRectangle2D.Double(3, 14, 7, 7, 3, 3));
                g2.draw(new RoundRectangle2D.Double(14, 14, 7, 7, 3, 3));
                break;
            case "email":
                g2.draw(new RoundRectangle2D.Double(2.5, 5, 19, 14, 4, 4));
                g2.draw(polyline(3, 6.5, 12, 13, 21, 6.5));
                break;
            case "image":
                g2.draw(new RoundRectangle2D.Double(3, 3, 18, 18, 5, 5));
                g2.fill(new Ellipse2D.Double(7, 7, 3.6, 3.6));
                g2.draw(polyline(21, 15.5, 16, 10.5, 5.5, 21));
                break;
            case "voice":
                g2.draw(new RoundRectangle2D.Double(9, 2.5, 6, 11.5, 6, 6));
                g2.draw(new Arc2D.Double(5, 4, 14, 14, 180, 180, Arc2D.OPEN));
                g2.draw(new Line2D.Double(12, 18, 12, 21.5));
                g2.draw(new Line2D.Double(8.5, 21.5, 15.5, 21.5));
                break;
            case "history":
                g2.draw(new Ellipse2D.Double(3, 3, 18, 18));
                g2.draw(polyline(12, 7, 12, 12, 15.5, 14));
                break;
            case "shield":
                Path2D shield = new Path2D.Double();
                shield.moveTo(12, 21.5);
                shield.curveTo(12, 21.5, 19.5, 18, 19.5, 12);
                shield.lineTo(19.5, 5.5);
                shield.lineTo(12, 2.5);
                shield.lineTo(4.5, 5.5);
                shield.lineTo(4.5, 12);
                shield.curveTo(4.5, 18, 12, 21.5, 12, 21.5);
                shield.closePath();
                g2.draw(shield);
                g2.draw(polyline(8.8, 12, 11, 14.2, 15.4, 9.6));
                break;
            case "scan":
                g2.draw(new Ellipse2D.Double(3.5, 3.5, 14, 14));
                g2.draw(new Line2D.Double(20.5, 20.5, 15.4, 15.4));
                break;
            case "clear":
                g2.draw(new Line2D.Double(6, 6, 18, 18));
                g2.draw(new Line2D.Double(18, 6, 6, 18));
                break;
            case "upload":
                g2.draw(polyline(3.5, 15, 3.5, 20.5, 20.5, 20.5, 20.5, 15));
                g2.draw(polyline(7.5, 8, 12, 3.5, 16.5, 8));
                g2.draw(new Line2D.Double(12, 3.5, 12, 15.5));
                break;
            case "refresh":
                g2.draw(new Arc2D.Double(4, 4, 16, 16, 50, 280, Arc2D.OPEN));
                g2.draw(polyline(18.8, 2.8, 17.6, 7.6, 12.8, 6.6));
                break;
            case "trash":
                g2.draw(new Line2D.Double(4, 6.5, 20, 6.5));
                g2.draw(polyline(6.2, 6.5, 7.2, 20.5, 16.8, 20.5, 17.8, 6.5));
                g2.draw(polyline(9, 6.5, 9.6, 3.5, 14.4, 3.5, 15, 6.5));
                g2.draw(new Line2D.Double(10.2, 10.5, 10.4, 16.8));
                g2.draw(new Line2D.Double(13.8, 10.5, 13.6, 16.8));
                break;
            case "alert":
                g2.draw(polygon(12, 3, 21.8, 20, 2.2, 20));
                g2.draw(new Line2D.Double(12, 9.5, 12, 13.5));
                g2.fill(new Ellipse2D.Double(10.8, 15.6, 2.4, 2.4));
                break;
            case "check":
                g2.draw(new Ellipse2D.Double(2.5, 2.5, 19, 19));
                g2.draw(polyline(8, 12.3, 10.8, 15.1, 16.2, 9.4));
                break;
            case "tick":
                g2.draw(polyline(5, 12.5, 9.8, 17.2, 19, 7.5));
                break;
            case "info":
                g2.draw(new Ellipse2D.Double(2.5, 2.5, 19, 19));
                g2.draw(new Line2D.Double(12, 11, 12, 16.5));
                g2.fill(new Ellipse2D.Double(10.8, 6.6, 2.4, 2.4));
                break;
            case "link":
                AffineTransform before = g2.getTransform();
                g2.rotate(-Math.PI / 4, 12, 12);
                g2.draw(new RoundRectangle2D.Double(2.5, 8.5, 10.5, 7, 7, 7));
                g2.draw(new RoundRectangle2D.Double(11, 8.5, 10.5, 7, 7, 7));
                g2.setTransform(before);
                break;
            case "layers":
                g2.draw(polygon(12, 2.5, 21.5, 7.5, 12, 12.5, 2.5, 7.5));
                g2.draw(polyline(2.5, 12, 12, 17, 21.5, 12));
                g2.draw(polyline(2.5, 16.5, 12, 21.5, 21.5, 16.5));
                break;
            case "file":
                g2.draw(new RoundRectangle2D.Double(4.5, 2.5, 15, 19, 4, 4));
                g2.draw(new Line2D.Double(8.5, 8, 15.5, 8));
                g2.draw(new Line2D.Double(8.5, 12, 15.5, 12));
                g2.draw(new Line2D.Double(8.5, 16, 13, 16));
                break;
            case "activity":
                g2.draw(polyline(22, 12, 18, 12, 15, 20, 9, 4, 6, 12, 2, 12));
                break;
            case "pie":
                g2.draw(new Ellipse2D.Double(3, 3, 18, 18));
                g2.draw(polyline(12, 3, 12, 12, 19.8, 16.5));
                break;
            case "bars":
                g2.draw(new Line2D.Double(6, 20, 6, 13));
                g2.draw(new Line2D.Double(12, 20, 12, 5));
                g2.draw(new Line2D.Double(18, 20, 18, 10));
                break;
            case "calendar":
                g2.draw(new RoundRectangle2D.Double(3, 4.5, 18, 16.5, 4, 4));
                g2.draw(new Line2D.Double(3, 9.5, 21, 9.5));
                g2.draw(new Line2D.Double(8, 2.5, 8, 6.5));
                g2.draw(new Line2D.Double(16, 2.5, 16, 6.5));
                break;
            case "target":
                g2.draw(new Ellipse2D.Double(2.5, 2.5, 19, 19));
                g2.draw(new Ellipse2D.Double(6.5, 6.5, 11, 11));
                g2.fill(new Ellipse2D.Double(10, 10, 4, 4));
                break;
            case "save":
                g2.draw(new RoundRectangle2D.Double(3.5, 3.5, 17, 17, 4, 4));
                g2.draw(polyline(7.5, 3.5, 7.5, 8.5, 15, 8.5, 15, 3.5));
                g2.draw(new RoundRectangle2D.Double(7, 13, 10, 7.5, 2, 2));
                break;
            default:
                g2.draw(new Ellipse2D.Double(4, 4, 16, 16));
        }
        g2.dispose();
    }

    private static Path2D polyline(double... points) {
        Path2D path = new Path2D.Double();
        path.moveTo(points[0], points[1]);
        for (int i = 2; i < points.length; i += 2) {
            path.lineTo(points[i], points[i + 1]);
        }
        return path;
    }

    private static Path2D polygon(double... points) {
        Path2D path = polyline(points);
        path.closePath();
        return path;
    }

    /** Draws the app logo (used for the window icon). */
    private static Image createAppIcon(int size) {
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = smooth(image.getGraphics());
        g2.setPaint(new GradientPaint(0, 0, CYAN, size, size, BLUE));
        g2.fill(new RoundRectangle2D.Double(0, 0, size, size, size * 0.45, size * 0.45));
        drawIcon(g2, "shield", (int) (size * 0.18), (int) (size * 0.18), (int) (size * 0.64), Color.WHITE);
        g2.dispose();
        return image;
    }

    // =====================================================================
    // REUSABLE WIDGETS
    // =====================================================================

    /** A panel with rounded corners and an optional border line. */
    public static class RoundedPanel extends JPanel {
        private final int radius;
        private Color fillColor;
        private Color borderColor;
        private int preferredWidthHint = -1;

        public RoundedPanel(LayoutManager layout) {
            this(layout, 20, BG_CARD, BORDER);
        }

        public RoundedPanel(LayoutManager layout, int radius, Color fillColor, Color borderColor) {
            super(layout);
            this.radius = radius;
            this.fillColor = fillColor;
            this.borderColor = borderColor;
            setOpaque(false);
        }

        public void setFillColor(Color color) {
            this.fillColor = color;
            repaint();
        }

        public void setBorderColor(Color color) {
            this.borderColor = color;
            repaint();
        }

        /** Makes GridBagLayout share space by weight instead of by content width. */
        public void setPreferredWidthHint(int width) {
            this.preferredWidthHint = width;
        }

        @Override
        public Dimension getPreferredSize() {
            Dimension size = super.getPreferredSize();
            if (preferredWidthHint > 0 && !isPreferredSizeSet()) {
                size.width = preferredWidthHint;
            }
            return size;
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            if (fillColor != null) {
                g2.setColor(fillColor);
                g2.fill(new RoundRectangle2D.Double(0, 0, getWidth() - 1, getHeight() - 1, radius, radius));
            }
            if (borderColor != null) {
                g2.setColor(borderColor);
                g2.draw(new RoundRectangle2D.Double(0.5, 0.5, getWidth() - 2, getHeight() - 2, radius, radius));
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }

    /** Rounded button in four styles, painted by hand so it never looks like default Swing. */
    public static class ModernButton extends JButton {
        public enum Style { PRIMARY, SECONDARY, DANGER, GHOST }

        private final Style style;
        private final String iconName;
        private boolean hover;

        public ModernButton(String text, String iconName, Style style) {
            super(text);
            this.style = style;
            this.iconName = iconName;
            setFont(font(Font.BOLD, 13.5f));
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setOpaque(false);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseEntered(MouseEvent e) {
                    hover = true;
                    repaint();
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    hover = false;
                    repaint();
                }
            });
        }

        @Override
        public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            int width = fm.stringWidth(getText()) + 40 + (iconName != null ? 26 : 0);
            return new Dimension(width, 42);
        }

        @Override
        public Dimension getMaximumSize() {
            return getPreferredSize();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth();
            int h = getHeight();
            if (!isEnabled()) {
                g2.setComposite(AlphaComposite.SrcOver.derive(0.45f));
            }
            RoundRectangle2D shape = new RoundRectangle2D.Double(0, 0, w - 1, h - 1, 12, 12);
            Color textColor;
            switch (style) {
                case PRIMARY:
                    g2.setPaint(new GradientPaint(0, 0, new Color(8, 145, 178), w, h, new Color(37, 99, 235)));
                    g2.fill(shape);
                    textColor = Color.WHITE;
                    break;
                case DANGER:
                    g2.setColor(withAlpha(RED, hover ? 52 : 30));
                    g2.fill(shape);
                    g2.setColor(withAlpha(RED, 140));
                    g2.draw(shape);
                    textColor = new Color(255, 160, 155);
                    break;
                case GHOST:
                    if (hover) {
                        g2.setColor(withAlpha(Color.WHITE, 14));
                        g2.fill(shape);
                    }
                    textColor = hover ? TEXT : TEXT_MUTED;
                    break;
                default: // SECONDARY
                    g2.setColor(BG_CARD_ALT);
                    g2.fill(shape);
                    g2.setColor(hover ? withAlpha(CYAN, 150) : BORDER);
                    g2.draw(shape);
                    textColor = TEXT;
            }
            if (isEnabled() && hover && style == Style.PRIMARY) {
                g2.setColor(withAlpha(Color.WHITE, 28));
                g2.fill(shape);
            }
            if (isEnabled() && getModel().isPressed()) {
                g2.setColor(withAlpha(Color.BLACK, 50));
                g2.fill(shape);
            }

            FontMetrics fm = g2.getFontMetrics(getFont());
            int textWidth = fm.stringWidth(getText());
            int contentWidth = textWidth + (iconName != null ? 26 : 0);
            int startX = (w - contentWidth) / 2;
            if (iconName != null) {
                drawIcon(g2, iconName, startX, (h - 17) / 2, 17, textColor);
                startX += 26;
            }
            g2.setFont(getFont());
            g2.setColor(textColor);
            g2.drawString(getText(), startX, (h - fm.getHeight()) / 2 + fm.getAscent());
            g2.dispose();
        }
    }

    /** One item of the sidebar menu. */
    private static class NavButton extends JComponent {
        private final String text;
        private final String iconName;
        private boolean selected;
        private boolean hover;

        NavButton(String text, String iconName, Runnable onClick) {
            this.text = text;
            this.iconName = iconName;
            setFont(font(Font.PLAIN, 14.5f));
            setAlignmentX(Component.LEFT_ALIGNMENT);
            setPreferredSize(new Dimension(240, 46));
            setMaximumSize(new Dimension(Integer.MAX_VALUE, 46));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseEntered(MouseEvent e) {
                    hover = true;
                    repaint();
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    hover = false;
                    repaint();
                }

                @Override
                public void mouseClicked(MouseEvent e) {
                    onClick.run();
                }
            });
        }

        void setSelected(boolean selected) {
            this.selected = selected;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int w = getWidth();
            int h = getHeight();
            RoundRectangle2D shape = new RoundRectangle2D.Double(14, 2, w - 28, h - 4, 12, 12);
            if (selected) {
                g2.setPaint(new GradientPaint(14, 0, withAlpha(CYAN, 46), w - 14, 0, withAlpha(BLUE, 12)));
                g2.fill(shape);
                g2.setColor(withAlpha(CYAN, 70));
                g2.draw(shape);
                g2.setColor(CYAN);
                g2.fill(new RoundRectangle2D.Double(0, 12, 4, h - 24, 4, 4));
            } else if (hover) {
                g2.setColor(withAlpha(Color.WHITE, 12));
                g2.fill(shape);
            }
            Color color = selected ? CYAN : hover ? TEXT : TEXT_MUTED;
            drawIcon(g2, iconName, 30, (h - 20) / 2, 20, color);
            g2.setFont(selected ? font(Font.BOLD, 14.5f) : getFont());
            g2.setColor(selected ? TEXT : color);
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(text, 62, (h - fm.getHeight()) / 2 + fm.getAscent());
            g2.dispose();
        }
    }

    /** The gradient logo square with a shield inside. */
    private static class LogoMark extends JComponent {
        private final int size;

        LogoMark(int size) {
            this.size = size;
            setPreferredSize(new Dimension(size, size));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int y = (getHeight() - size) / 2;
            g2.setColor(withAlpha(CYAN, 40));
            g2.fill(new RoundRectangle2D.Double(-3, y - 3, size + 6, size + 6, 18, 18));
            g2.setPaint(new GradientPaint(0, y, CYAN, size, y + size, BLUE));
            g2.fill(new RoundRectangle2D.Double(0, y, size, size, 14, 14));
            drawIcon(g2, "shield", 9, y + 9, size - 18, Color.WHITE);
            g2.dispose();
        }
    }

    /** A rounded square with a colored icon in the middle. */
    public static class IconBadge extends JComponent {
        private String iconName;
        private Color color;
        private final int size;

        public IconBadge(String iconName, int size, Color color) {
            this.iconName = iconName;
            this.size = size;
            this.color = color;
            setPreferredSize(new Dimension(size, size));
            setMinimumSize(new Dimension(size, size));
            setMaximumSize(new Dimension(size, size));
        }

        public void setIcon(String iconName, Color color) {
            this.iconName = iconName;
            this.color = color;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            int x = (getWidth() - size) / 2;
            int y = (getHeight() - size) / 2;
            RoundRectangle2D shape = new RoundRectangle2D.Double(x, y, size - 1, size - 1, size * 0.36, size * 0.36);
            g2.setPaint(new GradientPaint(x, y, withAlpha(color, 52), x + size, y + size, withAlpha(color, 16)));
            g2.fill(shape);
            g2.setColor(withAlpha(color, 90));
            g2.draw(shape);
            int iconSize = (int) (size * 0.5);
            drawIcon(g2, iconName, x + (size - iconSize) / 2, y + (size - iconSize) / 2, iconSize, color);
            g2.dispose();
        }
    }

    /** A small colored "pill" label, e.g. HIGH RISK. */
    public static class Pill extends JComponent {
        private String text;
        private Color color;

        public Pill(String text, Color color) {
            this.text = text;
            this.color = color;
            setFont(tracked(font(Font.BOLD, 11.5f), 0.05f));
        }

        public void setPill(String text, Color color) {
            this.text = text;
            this.color = color;
            revalidate();
            repaint();
        }

        @Override
        public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(getFont());
            return new Dimension(fm.stringWidth(text) + 34, fm.getHeight() + 10);
        }

        @Override
        public Dimension getMinimumSize() {
            return getPreferredSize();
        }

        @Override
        public Dimension getMaximumSize() {
            return getPreferredSize();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            Dimension size = getPreferredSize();
            int y = (getHeight() - size.height) / 2;
            RoundRectangle2D shape = new RoundRectangle2D.Double(0, y, size.width - 1, size.height - 1, size.height, size.height);
            g2.setColor(withAlpha(color, 34));
            g2.fill(shape);
            g2.setColor(withAlpha(color, 120));
            g2.draw(shape);
            g2.setColor(color);
            g2.fillOval(11, y + size.height / 2 - 3, 6, 6);
            g2.setFont(getFont());
            FontMetrics fm = g2.getFontMetrics();
            g2.drawString(text, 23, y + (size.height - fm.getHeight()) / 2 + fm.getAscent());
            g2.dispose();
        }
    }

    /** Single-line text field with rounded corners, a placeholder hint and an optional icon. */
    public static class HintTextField extends JTextField {
        private final String hint;
        private final String iconName;
        private boolean focused;

        public HintTextField(String hint, String iconName) {
            this.hint = hint;
            this.iconName = iconName;
            setOpaque(false);
            setFont(font(Font.PLAIN, 14));
            setForeground(TEXT);
            setCaretColor(CYAN);
            setSelectionColor(withAlpha(CYAN, 90));
            setSelectedTextColor(Color.WHITE);
            setBorder(new EmptyBorder(11, iconName != null ? 42 : 14, 11, 14));
            addFocusListener(new FocusAdapter() {
                @Override
                public void focusGained(FocusEvent e) {
                    focused = true;
                    repaint();
                }

                @Override
                public void focusLost(FocusEvent e) {
                    focused = false;
                    repaint();
                }
            });
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = smooth(g);
            RoundRectangle2D shape = new RoundRectangle2D.Double(0.5, 0.5, getWidth() - 2, getHeight() - 2, 14, 14);
            g2.setColor(BG_INPUT);
            g2.fill(shape);
            g2.setColor(focused ? withAlpha(CYAN, 170) : BORDER);
            g2.draw(shape);
            if (iconName != null) {
                drawIcon(g2, iconName, 15, (getHeight() - 18) / 2, 18, focused ? CYAN : TEXT_DIM);
            }
            g2.dispose();

            super.paintComponent(g);

            if (getText().isEmpty() && hint != null) {
                Graphics2D g3 = smooth(g);
                g3.setFont(getFont());
                g3.setColor(TEXT_DIM);
                Insets insets = getInsets();
                FontMetrics fm = g3.getFontMetrics();
                g3.drawString(hint, insets.left + 2, (getHeight() - fm.getHeight()) / 2 + fm.getAscent());
                g3.dispose();
            }
        }
    }

    /** Multi-line text area that shows a grey hint while it is empty. */
    public static class HintTextArea extends JTextArea {
        private final String hint;

        public HintTextArea(String hint) {
            this.hint = hint;
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (getText().isEmpty() && hint != null) {
                Graphics2D g2 = smooth(g);
                g2.setFont(getFont());
                g2.setColor(TEXT_DIM);
                FontMetrics fm = g2.getFontMetrics();
                Insets insets = getInsets();
                int y = insets.top + fm.getAscent();
                for (String line : hint.split("\n")) {
                    g2.drawString(line, insets.left + 2, y);
                    y += fm.getHeight();
                }
                g2.dispose();
            }
        }
    }

    /** Thin rounded scrollbar without arrow buttons. */
    public static class ModernScrollBarUI extends BasicScrollBarUI {
        @Override
        protected void configureScrollBarColors() {
            thumbColor = new Color(52, 68, 102);
            trackColor = new Color(0, 0, 0, 0);
        }

        @Override
        protected JButton createDecreaseButton(int orientation) {
            return createInvisibleButton();
        }

        @Override
        protected JButton createIncreaseButton(int orientation) {
            return createInvisibleButton();
        }

        private JButton createInvisibleButton() {
            JButton button = new JButton();
            Dimension zero = new Dimension(0, 0);
            button.setPreferredSize(zero);
            button.setMinimumSize(zero);
            button.setMaximumSize(zero);
            return button;
        }

        @Override
        protected void paintTrack(Graphics g, JComponent c, Rectangle bounds) {
            // transparent track
        }

        @Override
        protected void paintThumb(Graphics g, JComponent c, Rectangle bounds) {
            if (bounds.isEmpty() || !scrollbar.isEnabled()) {
                return;
            }
            Graphics2D g2 = smooth(g);
            g2.setColor(isThumbRollover() ? new Color(80, 100, 142) : thumbColor);
            g2.fill(new RoundRectangle2D.Double(bounds.x + 2, bounds.y + 2, bounds.width - 4, bounds.height - 4, 8, 8));
            g2.dispose();
        }
    }

    /** A panel that always matches the width of its scroll pane (so text can wrap). */
    public static class ScrollablePanel extends JPanel implements Scrollable {
        public ScrollablePanel(LayoutManager layout) {
            super(layout);
            setOpaque(false);
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return new Dimension(300, 300); // the real size comes from the surrounding layout
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 18;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return Math.max(visibleRect.height - 40, 40);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    /** Centered JLabel helper used for empty states. */
    public static JLabel createCenteredLabel(String text, Font font, Color color) {
        JLabel label = createLabel(text, font, color);
        label.setHorizontalAlignment(SwingConstants.CENTER);
        label.setAlignmentX(Component.CENTER_ALIGNMENT);
        return label;
    }
}
