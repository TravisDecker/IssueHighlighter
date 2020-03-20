package burp.issuehighlighter;

import burp.IInterceptedProxyMessage;

public interface ScanToolI {

  String getToolName();

  void processMessage(boolean messageIsRequest, IInterceptedProxyMessage message);

  void setHighlightColor(ColorEnum colorEnum);

  void saveToolDefaults();

  ColorEnum getColorEnum();


}
