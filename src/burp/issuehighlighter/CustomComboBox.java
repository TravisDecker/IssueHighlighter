package burp.issuehighlighter;

import java.util.Vector;
import javax.swing.ComboBoxModel;
import javax.swing.JComboBox;

public class CustomComboBox extends JComboBox {

  private ScanToolI scanTool;

  public CustomComboBox(Object[] items, ScanToolI scanTool) {
    super(items);
    this.scanTool = scanTool;
  }

  public CustomComboBox(ComboBoxModel aModel) {
    super(aModel);
  }

  public CustomComboBox(Object[] items) {
    super(items);
  }

  public CustomComboBox(Vector items) {
    super(items);
  }

  public CustomComboBox() {
    super();
  }

  public ScanToolI getScanTool() {
    return scanTool;
  }
}
