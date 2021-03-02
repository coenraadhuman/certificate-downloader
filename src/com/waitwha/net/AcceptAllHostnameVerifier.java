package com.waitwha.net;

import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import com.waitwha.logging.LogManager;

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
 * @package com.waitwha.net
 */
public class AcceptAllHostnameVerifier 
	implements HostnameVerifier {

	private static final Logger log = 
		LogManager.getLogger(AcceptAllHostnameVerifier.class);
	
	/**
	 * @see javax.net.ssl.HostnameVerifier#verify(java.lang.String, javax.net.ssl.SSLSession)
	 */
	@Override
	public boolean verify(String hostname, SSLSession session) {
		log.fine(this.getClass().getName() +".verify(): Verified (without check) hostname "+ hostname +" for peer host "+ session.getPeerHost());
		return true;
	}

}
