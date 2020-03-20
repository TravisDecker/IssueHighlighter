package burp.issuehighlighter;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IResponseInfo;
import java.io.PrintWriter;

public class TestTool implements ScanToolI {

  IBurpExtenderCallbacks callbacks;
  IExtensionHelpers helpers;
  PrintWriter stdout;
  PrintWriter stderr;
  String highlightColor;

  public TestTool(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
      PrintWriter stdout, PrintWriter stderr) {
    this.callbacks = callbacks;
    this.helpers = helpers;
    this.stdout = stdout;
    this.stderr = stderr;
    if (callbacks.loadExtensionSetting("init_load") == null) {
      saveToolDefaults();
    }

  }

  @Override
  public String getToolName() {
    return "Test Tool";
  }

  @Override
  public void processMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
    if (!messageIsRequest) {
      IHttpRequestResponse messageInfo = message.getMessageInfo();
      IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());
      int code = respInfo.getStatusCode();
      if (code < 200) {
        messageInfo.setHighlight("green");
      }
    }
  }

  @Override
  public void setHighlightColor(ColorEnum colorEnum) {
    callbacks.saveExtensionSetting("test_tool_highlight_color", colorEnum.getColor());
    this.highlightColor = colorEnum.getColor();
    stdout.println("Color Updated to " + highlightColor);
  }

  @Override
  public void saveToolDefaults() {
    callbacks.saveExtensionSetting("test_tool_enabled", "true");
    callbacks.saveExtensionSetting("test_tool_highlight_color", "red");
  }

  @Override
  public ColorEnum getColorEnum() {
    return null;
  }

}
