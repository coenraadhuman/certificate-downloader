package com.waitwha.utils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;

/**
 * <h1>CertDownload</h1>
 * <small>Copyright &copy;2014 Mike Duncan <a href="mailto:mike.duncan@waitwha.com">mike.duncan@waitwha.com</a>.</small><p />
 *
 * <pre>
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * </pre>
 *
 * TODO Document this class/interface.
 *
 * @author Mike Duncan <mike.duncan@waitwha.com>
 * @version $Id$
 * @package com.waitwha.utils
 */
public final class StringUtils {
	
	private StringUtils() { }

	/**
	 * Capitalizes the first letter in the given String.
	 * 
	 * @param a		String subject
	 * @return		String result
	 */
	public static final String toFirstUpperCase(String a)  {
		return a.substring(0, 1).toUpperCase() + a.substring(1).toLowerCase();
	}
	
	/**
	 * Returns a String for the given String[] which is comma delimited. 
	 * 
	 * @param		subject		The String to parse.
	 * @return	String[]
	 */
	public static final String arrayToString(Object[] subject)  {
		String ret = "";
		for(Object s : subject)
			ret += s.toString() +",";
		
		return ret.substring(0, (ret.length() - 1));
	}
	
	/**
	 * Returns a String[] for the given String, parsing by commas.
	 * 
	 * @param		subject		The String[] to parse.
	 * @return	String
	 */
	public static final String[] stringToArray(String subject)  {
		return subject.split(",");
	}
	
	/**
	 * Appends an String value to the end of the given String[] subject.
	 * 
	 * @param		subject		String[] to append too.
	 * @param		addition	String to append to String[] subject.
	 * @return	String[]
	 */
	public static final String[] appendToArray(String[] subject, String addition)  {
		String s = StringUtils.arrayToString(subject);
		s += ","+ addition;
		return StringUtils.stringToArray(s);
	}
	
	/**
	 * Returns whether or not the given needle exists within the haystack (String[]).
	 * 
	 * @param		haystack		String[] to search.
	 * @param		needle			String to look for within String[].
	 * @return	boolean
	 */
	public static final boolean contains(String[] haystack, String needle)  {
		for(String n : haystack)
			if(n.equals(needle))
				return true;
		
		return false;
	}
	
	/**
	 * Attempts to remove all white spaces from the given String.
	 * 
	 * @param input			String to strip.
	 * @return					String which is stripped of all white spaces.
	 */
	public static final String removeWhiteSpaces(String input)  {
		input = input.trim();
		StringBuffer buffer = new StringBuffer();
		for(int i = 0; i < input.length(); i++)
			if(! input.substring(i, 1).equals(" "))
				buffer.append(input.substring(i, 1));
		
		return buffer.toString();
	}
	
	/**
	 * Converts the given String to Hex format. 
	 * 
	 * @param str			String to convert to Hex.
	 * @return				String Hex formatted version of given String.
	 */
	public static final String toHex(String str)  {
		return String.format("%x", new BigInteger(1, str.getBytes()));
	}
	
	/**
	 * Attempts to convert the given String to binary (i.e 01100100) format.
	 * 
	 * @param str			String to convert.
	 * @return				Converted String.
	 */
	public static final String toBinary(String str)  {
		StringBuilder buffer = new StringBuilder();
		byte[] bytes = str.getBytes();
		for(byte b : bytes)  {
			int v = b;
			for(int i = 0; i < 8; i++)  {
				buffer.append((v & 128) == 0 ? 0 : 1);
				v <<= 1;
			}
		}
		
		return buffer.toString();
	}
	
	public static final String toString(Exception e)  {
		StringWriter writer = new StringWriter();
		e.printStackTrace(new PrintWriter(writer));
		
		return writer.toString();
	}
	
}
