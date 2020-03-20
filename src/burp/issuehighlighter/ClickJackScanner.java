package burp.issuehighlighter;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IResponseInfo;
import java.io.PrintWriter;
import java.util.List;

public class ClickJackScanner implements ScanToolI {

  IBurpExtenderCallbacks callbacks;
  IExtensionHelpers helpers;
  PrintWriter stdout;
  PrintWriter stderr;
  ColorEnum color;

  public ClickJackScanner(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers,
      PrintWriter stdout, PrintWriter stderr) {
    this.callbacks = callbacks;
    this.helpers = helpers;
    this.stdout = stdout;
    this.stderr = stderr;
    if (callbacks.loadExtensionSetting("init_load") == null) {
      saveToolDefaults();
    }

    String savedColor = callbacks.loadExtensionSetting("click_jack_scanner_highlight_color");

    for (ColorEnum co : ColorEnum.values()
    ) {
      if (co.getColor().equals(savedColor)) {
        color = co;
      }
    }
  }

  @Override
  public String getToolName() {
    return "Click Jack Scanner";
  }

  @Override
  public void processMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
    if (!messageIsRequest) {
      IHttpRequestResponse messageInfo = message.getMessageInfo();
      IResponseInfo respInfo = helpers.analyzeResponse(messageInfo.getResponse());

      if (checkResponseEligibility(respInfo) && !checkResponseHeader(respInfo.getHeaders())) {
        messageInfo.setHighlight(color.getColor());

      }
    }
  }

  @Override
  public void setHighlightColor(ColorEnum colorEnum) {
    callbacks.saveExtensionSetting("click_jack_scanner_highlight_color", colorEnum.getColor());
    this.color = colorEnum;
  }

  @Override
  public void saveToolDefaults() {
    callbacks.saveExtensionSetting("click_jack_scanner_enabled", "true");
    callbacks.saveExtensionSetting("click_jack_scanner_highlight_color", ColorEnum.CYAN.getColor());
  }

  @Override
  public ColorEnum getColorEnum() {
    return color;
  }

  // Extra MIME types may be unnecessary.
  // pull out hard coded status codes
  private boolean checkResponseEligibility(IResponseInfo respInfo) {
    if (respInfo.getStatusCode() >= 200 && respInfo.getStatusCode() < 300) {
      switch (respInfo.getInferredMimeType()) {
        case "text":
        case "html":
        case "HTML":
          return true;
      }
    }
    return false;
  }

  //Maybe pass the wanted header as a param
  private boolean checkResponseHeader(List<String> headers) {
    return headers.stream().anyMatch(header -> header.matches("X-Frame-Options.*"));
  }


}


