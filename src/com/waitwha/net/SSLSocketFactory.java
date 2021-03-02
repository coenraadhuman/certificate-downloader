package com.waitwha.net;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.logging.Logger;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

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
 * Custom SocketFactory derivation which will handle the SSL connections.
 *
 * @author Mike Duncan <mike.duncan@waitwha.com>
 * @version $Id$
 * @package com.waitwha.net
 */
public class SSLSocketFactory extends SocketFactory {
	
	private static final Logger log = LogManager.getLogger(SSLSocketFactory.class);
	private static SSLSocketFactory instance;
	
	public static final int DEFAULT_TIMEOUT = 10000; //10s
	
	public static final String[] PROTOCOLS = {
		"TLSv1",
		"TLS",
		"SSLv3",
		"SSL"
	};
	
	public class KeyManagers extends ArrayList<KeyManager>  {
		private static final long serialVersionUID = 1L;
		
		public KeyManager[] getKeyManagers()  {
			if(this.size() == 0)
				return null;
			
			KeyManager[] ret = new KeyManager[this.size()];
			int i = 0;
			for(KeyManager km : this)
				ret[i++] = km;
			
			return ret;
		}
	}
	
	public class TrustManagers extends ArrayList<TrustManager>  {
		private static final long serialVersionUID = 1L;
		
		public TrustManager[] getTrustManagers()  {
			if(this.size() == 0)
				return null;
			
			TrustManager[] ret = new TrustManager[this.size()];
			int i = 0;
			for(TrustManager tm : this)
				ret[i++] = tm;
			
			return ret;
		}
	}
	
	private int timeout;
	private SSLContext context;
	private KeyManagers keyManagers;
	private TrustManagers trustManagers;
	private boolean initContext;
	private KeyStore keyStore;
	
	private SSLSocketFactory()  {
		this.timeout = DEFAULT_TIMEOUT;
		this.keyManagers = new KeyManagers();
		this.trustManagers = new TrustManagers();
		
		int i = 0;
		while(this.context == null)  {
			try {
				this.context = SSLContext.getInstance(PROTOCOLS[i], "SunJSSE");
				log.fine(String.format("Protocol support: %s", PROTOCOLS[i]));
				
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				log.warning(String.format("Unable to load protocol %s: %s %s", PROTOCOLS[i], e.getClass().getName(), e.getMessage()));
			
			}
			
			i++;
			if(i >= PROTOCOLS.length)  {
				log.warning("Could not load any valid protocols. Connections will likely fail!  :(  ");
				break;
			}
		}
		
		this.initContext = false;
	}
	
	public int getTimeout()  {
		return this.timeout;
	}
	
	public void setTimeout(int timeout)  {
		this.timeout = timeout;
	}
	
	public static final SSLSocketFactory getDefaultFactory() {
		if(instance == null)
			instance = new SSLSocketFactory();
		
		return instance;
	}
	
	public static final SSLSocketFactory getCustomFactory(int timeout)  {
		SSLSocketFactory factory = SSLSocketFactory.getDefaultFactory();
		factory.setTimeout(timeout);
		return factory;
	}
	
	public void setKeyStore(KeyStore ks)  {
		try {
			KeyManagerFactory factory = 
				KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			this.keyStore = ks;
			factory.init(ks.getStore(), ks.getPassword());
			for(KeyManager m : factory.getKeyManagers())  {
				log.fine("Loading KeyManager: "+ m.getClass().getName());
				this.keyManagers.add(m);
			}
			
		}catch(Exception e) {
			log.warning("Could not set KeyStore to "+ ks +": "+ e.getMessage());
		}
	}
	
	public KeyStore getKeyStore()  {
		return this.keyStore;
	}
	
	public void addKeyManager(KeyManager km)  {
		this.keyManagers.add(km);
	}
	
	public KeyManagers getKeyManagers()  {
		return this.keyManagers;
	}
	
	public void addTrustManager(TrustManager tm)  {
		this.trustManagers.add(tm);
	}
	
	public TrustManagers getTrustManagers()  {
		return this.trustManagers;
	}
	
	private SSLSocket createSocket(String host, int port, int timeout) 
			throws KeyManagementException, IOException, UnknownHostException {
		if(!this.initContext)  {
			
			//If there is no KeyStore, we will need to use a custom one.
			if(this.keyManagers.size() == 0)  {
				try {
					this.setKeyStore(new InMemoryKeyStore());
				} catch (KeyStoreException | NoSuchAlgorithmException
						| CertificateException e) {
					log.warning(String.format("Could not load memory-based keystore: %s", e.getMessage()));
				}
			}
			
			//If there are no trust managers present at this point, we will go ahead and accept all.
			if(this.trustManagers.size() == 0)  {
				this.trustManagers.add(new AcceptAllX509TrustManager());
				log.fine("No specified trust management, defaulting to accepting all certificates.");
			}
			
			this.context.init(this.keyManagers.getKeyManagers(), this.trustManagers.getTrustManagers(), null);
			log.fine(String.format("Initialized SSLContext: %s, %s", this.context.getProtocol(), this.context.getProvider().getClass().getName()));
			this.initContext = true;
		}
		
		javax.net.ssl.SSLSocketFactory factory = this.context.getSocketFactory();
		SSLSocket s = (SSLSocket)factory.createSocket(host, port);
		s.setSoTimeout(timeout);
		return s;
	}

	@Override
	public Socket createSocket(String host, int port) 
			throws IOException, UnknownHostException {
		try {
			return this.createSocket(host, port, this.timeout);
			
		} catch (KeyManagementException e) {
			log.warning("Could not create socket due to key management issues: "+ e.getMessage());
		}
		
		return null;
	}

	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		try {
			return this.createSocket(host.getHostAddress(), port, this.timeout);
		} catch (KeyManagementException e) {
			log.warning("Could not create socket due to key management issues: "+ e.getMessage());
		}
		
		return null;
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localhost, int localport)
			throws IOException, UnknownHostException {
		try {
			return this.createSocket(host, port, this.timeout);
		} catch (KeyManagementException e) {
			log.warning("Could not create socket due to key management issues: "+ e.getMessage());
		}
		
		return null;
	}

	@Override
	public Socket createSocket(InetAddress host, int port, InetAddress localhost, int localport) 
			throws IOException {
		try {
			return this.createSocket(host.getHostAddress(), port, this.timeout);
		} catch (KeyManagementException e) {
			log.warning("Could not create socket due to key management issues: "+ e.getMessage());
		}
		
		return null;
	}

}
