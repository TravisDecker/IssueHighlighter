package issuehighlighter;

public enum ColorEnum {

  PINK(0, "pink"),
  MAGENTA(1, "magenta"),
  RED(2, "red"),
  ORANGE(3, "orange"),
  YELLOW(4, "yellow"),
  GREEN(5, "green"),
  BLUE(6, "blue"),
  CYAN(7, "cyan"),
  GRAY(8, "gray");


  private int index;
  private String color;

  ColorEnum(int index, String color) {
    this.index = index;
    this.color = color;
  }

  public String getColor() {
    return color;
  }


  public int getIndex() {
    return index;
  }
}
