package com.github.coenraadhuman.certificatedownloader.utils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;

public final class StringUtils {

  private StringUtils() {}

  /**
   * Capitalizes the first letter in the given String.
   *
   * @param a String subject
   * @return String result
   */
  public static final String toFirstUpperCase(String a) {
    return a.substring(0, 1).toUpperCase() + a.substring(1).toLowerCase();
  }

  /**
   * Returns a String for the given String[] which is comma delimited.
   *
   * @param subject The String to parse.
   * @return String[]
   */
  public static final String arrayToString(Object[] subject) {
    String ret = "";
    for (Object s : subject) ret += s.toString() + ",";

    return ret.substring(0, (ret.length() - 1));
  }

  /**
   * Returns a String[] for the given String, parsing by commas.
   *
   * @param subject The String[] to parse.
   * @return String
   */
  public static final String[] stringToArray(String subject) {
    return subject.split(",");
  }

  /**
   * Appends an String value to the end of the given String[] subject.
   *
   * @param subject String[] to append too.
   * @param addition String to append to String[] subject.
   * @return String[]
   */
  public static final String[] appendToArray(String[] subject, String addition) {
    String s = StringUtils.arrayToString(subject);
    s += "," + addition;
    return StringUtils.stringToArray(s);
  }

  /**
   * Returns whether or not the given needle exists within the haystack (String[]).
   *
   * @param haystack String[] to search.
   * @param needle String to look for within String[].
   * @return boolean
   */
  public static final boolean contains(String[] haystack, String needle) {
    for (String n : haystack) if (n.equals(needle)) return true;

    return false;
  }

  /**
   * Attempts to remove all white spaces from the given String.
   *
   * @param input String to strip.
   * @return String which is stripped of all white spaces.
   */
  public static final String removeWhiteSpaces(String input) {
    input = input.trim();
    StringBuffer buffer = new StringBuffer();
    for (int i = 0; i < input.length(); i++)
      if (!input.substring(i, 1).equals(" ")) buffer.append(input, i, 1);

    return buffer.toString();
  }

  /**
   * Converts the given String to Hex format.
   *
   * @param str String to convert to Hex.
   * @return String Hex formatted version of given String.
   */
  public static final String toHex(String str) {
    return String.format("%x", new BigInteger(1, str.getBytes()));
  }

  /**
   * Attempts to convert the given String to binary (i.e 01100100) format.
   *
   * @param str String to convert.
   * @return Converted String.
   */
  public static final String toBinary(String str) {
    StringBuilder buffer = new StringBuilder();
    byte[] bytes = str.getBytes();
    for (byte b : bytes) {
      int v = b;
      for (int i = 0; i < 8; i++) {
        buffer.append((v & 128) == 0 ? 0 : 1);
        v <<= 1;
      }
    }

    return buffer.toString();
  }

  public static final String toString(Exception e) {
    StringWriter writer = new StringWriter();
    e.printStackTrace(new PrintWriter(writer));

    return writer.toString();
  }
}
