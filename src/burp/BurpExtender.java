package burp;

import burp.issuehighlighter.ClickJackScanner;
import burp.issuehighlighter.ColorEnum;
import burp.issuehighlighter.CustomComboBox;
import burp.issuehighlighter.ScanToolI;
import burp.issuehighlighter.UserAgentReflection;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IProxyListener, ITab,
    ListSelectionListener, ActionListener {

  IBurpExtenderCallbacks callbacks;
  IExtensionHelpers helpers;
  PrintWriter stdout;
  PrintWriter stderr;
  JPanel mainPanel;
  List<ScanToolI> scanTools = new ArrayList<>();

  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    this.callbacks = callbacks;
    this.helpers = callbacks.getHelpers();
    stdout = new PrintWriter(callbacks.getStdout(), true);
    stderr = new PrintWriter(callbacks.getStderr(), true);
    callbacks.setExtensionName("Issue Highlighter");
    callbacks.registerExtensionStateListener(this);
    callbacks.saveExtensionSetting("init_load", null);
    loadTools();
    buildGUI();
  }


  private void buildGUI() {

    SwingUtilities.invokeLater(new Runnable() {
      @Override
      public void run() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

        //comboBox.getScanTool()
        //comboBox.setSelectedIndex(6);
        // checkBox.addActionListener(BurpExtender.this::actionPerformed);
        scanTools.forEach(st -> {
          buildToolPanel(st);
        });

        //  Filler Panel used to fill in extra space, prevents the other components from spreading out.
        JPanel fillerPanel = new JPanel();
        fillerPanel.setPreferredSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        mainPanel.add(fillerPanel);
        callbacks.customizeUiComponent(mainPanel);

        // add the custom tab to Burp's UI
        callbacks.addSuiteTab(BurpExtender.this);
        // register ourselves as an HTTP listener
        callbacks.registerProxyListener(BurpExtender.this);
      }
    });


  }

  private void buildToolPanel(ScanToolI st) {
    JPanel toolPanel = new JPanel();
    toolPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
    JCheckBox checkBox = new JCheckBox("Enable " + st.getToolName());

    List<String> colors = new ArrayList<>();
    for (ColorEnum co : ColorEnum.values()
    ) {
      colors.add(co.getColor());
    }

    CustomComboBox comboBox = new CustomComboBox(colors.toArray(), st);

    JLabel colorLabel = new JLabel(
        "Select a highlight color for potential " + st.getToolName() + " issues");
    comboBox.addActionListener(BurpExtender.this);
    toolPanel.add(checkBox);
    toolPanel.add(colorLabel);
    toolPanel.add(comboBox);
    toolPanel.setVisible(true);
    mainPanel.add(toolPanel);
  }


  private void loadTools() {
    ClickJackScanner clickJackScanner = new ClickJackScanner(callbacks, helpers, stdout, stderr);
    //TestTool testTool = new TestTool(callbacks, helpers, stdout, stderr);
    UserAgentReflection userAgentReflection = new UserAgentReflection(callbacks, helpers, stdout,
        stderr);

    scanTools.add(clickJackScanner);
    scanTools.add(userAgentReflection);
    //scanTools.add(testTool);
    callbacks.saveExtensionSetting("init_load", "false");

  }


  @Override
  public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {

    for (ScanToolI st : scanTools
    ) {
      st.processMessage(messageIsRequest, message);
    }
  }

  @Override
  public String getTabCaption() {
    return "Issue Highlighter";
  }

  @Override
  public Component getUiComponent() {
    return mainPanel;
  }

  @Override
  public void valueChanged(ListSelectionEvent e) {

  }

  @Override
  public void actionPerformed(ActionEvent e) {
    CustomComboBox jBox = (CustomComboBox) e.getSource();
    int idx = jBox.getSelectedIndex();
    jBox.getScanTool().setHighlightColor(ColorEnum.values()[idx]);
  }


  @Override
  public void extensionUnloaded() {

  }
}
