package com.waitwha.net;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.logging.Logger;

import javax.net.ssl.X509TrustManager;

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
public class AcceptAllX509TrustManager 
	implements X509TrustManager {
	
	private static final Logger log = 
		LogManager.getLogger(AcceptAllX509TrustManager.class);

	private ArrayList<X509Certificate> issuers;
	
	public AcceptAllX509TrustManager()  {
		super();
		this.issuers = new ArrayList<X509Certificate>();
	}
	
	/**
	 * @return the issuers
	 */
	public ArrayList<X509Certificate> getIssuers() {
		return issuers;
	}
	
	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		
		for(X509Certificate cert : chain)  {
			log.fine("Downloaded/Saved "+ authType +" certificate: "+ cert.getSubjectDN());
			this.issuers.add(cert);
		}
		
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		
		for(X509Certificate cert : chain)  {
			log.fine("Downloaded/Saved "+ authType +" certificate: "+ cert.getSubjectDN());
			this.issuers.add(cert);
		}
		
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		X509Certificate[] ret = new X509Certificate[this.issuers.size()];
		issuers.toArray(ret);
		return ret;
	}
	
}
