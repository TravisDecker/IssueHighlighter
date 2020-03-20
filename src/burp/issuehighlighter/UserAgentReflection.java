package burp.issuehighlighter;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import java.io.PrintWriter;
import java.util.List;
import java.util.stream.Collectors;

public class UserAgentReflection implements ScanToolI {

  IBurpExtenderCallbacks callbacks;
  IExtensionHelpers helpers;
  PrintWriter stdout;
  PrintWriter stderr;
  ColorEnum color;


  public UserAgentReflection(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
      PrintWriter stdout, PrintWriter stderr) {
    this.callbacks = callbacks;
    this.helpers = helpers;
    this.stdout = stdout;
    this.stderr = stderr;
    if (callbacks.loadExtensionSetting("init_load") == null) {
      saveToolDefaults();
      //stdout.println("Save def called user agent");
    }

    String savedColor = callbacks.loadExtensionSetting("user_agent_reflection_highlight_color");

    for (ColorEnum co : ColorEnum.values()
    ) {
      if (co.getColor().equals(savedColor)) {
        color = co;
      }
    }
  }

  @Override
  public String getToolName() {
    return "User Agent Reflection";
  }

  @Override
  public void processMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
    String userAgent = null;
    IHttpRequestResponse messageInfo = message.getMessageInfo();
    List<String> reqHeaders = helpers.analyzeRequest(messageInfo.getRequest()).getHeaders()
        .stream()
        .filter(s -> s.contains("User-Agent:"))
        .collect(Collectors.toList());

    if (reqHeaders.size() > 0) {
      userAgent = reqHeaders.get(0);
    }

    userAgent = userAgent.substring(12);
    byte[] byts = messageInfo.getResponse();

    String responseStr = null;
    if (byts != null) {
      responseStr = helpers.bytesToString(byts);
      if (responseStr.contains(userAgent)) {
        messageInfo.setHighlight(color.getColor());
      }
    }


  }

  @Override
  public void setHighlightColor(ColorEnum colorEnum) {
    callbacks.saveExtensionSetting("user_agent_reflection_highlight_color", colorEnum.getColor());
    this.color = colorEnum;
  }

  @Override
  public void saveToolDefaults() {
    callbacks.saveExtensionSetting("user_agent_reflection_enabled", "true");
    callbacks
        .saveExtensionSetting("user_agent_reflection_highlight_color", ColorEnum.ORANGE.getColor());
  }

  @Override
  public ColorEnum getColorEnum() {
    return color;
  }
}
