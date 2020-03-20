package burp.issuehighlighter;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IInterceptedProxyMessage;
import java.io.PrintWriter;

public abstract class ScanTool {

  IBurpExtenderCallbacks callbacks;
  IExtensionHelpers helpers;
  PrintWriter stdout;
  PrintWriter stderr;
  String highlightColor;
  String toolName;
  String enabledString;
  String defaultColor;
  String defaultColorKey;
  String enabledKey;


  public ScanTool(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, PrintWriter stdout,
      PrintWriter stderr, String toolName, String enabledString) {
    this.callbacks = callbacks;
    this.helpers = helpers;
    this.stdout = stdout;
    this.stderr = stderr;
    this.toolName = toolName;
    this.enabledString = enabledString;
  }

  public String getToolName() {
    return toolName;
  }

  public String getEnabledString() {
    return enabledString;
  }

  public abstract void processMessage(boolean messageIsRequest, IInterceptedProxyMessage message);

  public abstract void setHighlightColor(String extensionSetting);

  public abstract void saveToolDefaults();

}
