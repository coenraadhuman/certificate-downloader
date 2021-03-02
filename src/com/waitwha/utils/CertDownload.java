package com.waitwha.utils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;

import com.waitwha.logging.LogManager;
import com.waitwha.net.AcceptAllX509TrustManager;
import com.waitwha.net.KeyStore;
import com.waitwha.net.SSLSocketFactory;

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
public class CertDownload implements Runnable {
	
	private static final Logger log = LogManager.getLogger(CertDownload.class);
	private static String host;
	private static int port;
	private static boolean storeEachCert;
	private static boolean storeAsKeyStore;
	private static char[] password;
	private static String path;
	
	/**
	 * Uses the custom SSLSocketFactory, which will use an instance of AcceptAllX509TrustManager which 
	 * will capture all of the TLS/SSL certificates if a connection is made and the handshake completes.
	 * 
	 */
	@Override
	public void run() {
		SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefaultFactory();
		log.info(String.format("Connecting to %s:%d;  please wait...", host, port));
		try(SSLSocket s = (SSLSocket)factory.createSocket(host, port))  {
			s.startHandshake();
			log.info(String.format("Connection to %s:%d completed successfully.", host, port));
			
			AcceptAllX509TrustManager tm = (AcceptAllX509TrustManager)factory.getTrustManagers().get(0);
			log.info(String.format("Retrieved %d certificate(s) from server.", tm.getIssuers().size()));
			
			for(X509Certificate cert : tm.getIssuers())  {
				if (storeEachCert) {
					String filename = System.getProperty("user.dir")
							+ System.getProperty("file.separator")
							+ cert.getSubjectDN().toString() + ".cer";
					try (FileOutputStream fos = new FileOutputStream(filename)) {
						fos.write(cert.getEncoded());

					} catch (IOException e) {
						log.warning(String
								.format("Unable to save certificate to filesystem '%s': %s",
										filename, e.getMessage()));

					}
				}
			}
			
			if(storeAsKeyStore)  {
				KeyStore ks = factory.getKeyStore();
				for(X509Certificate cert : tm.getIssuers())
					ks.add(cert, UUID.randomUUID().toString());
				
				ks.save(path, password);
				log.info(String.format("Successfully saved keystore to %s using password '%s'.", path, password));
			}
			
		} catch (IOException e) {
			log.warning(String.format("Connection failed to %s:%d; %s", host, port, e.getMessage()));
			
		} catch (KeyStoreException e) {
			log.warning(String.format("Unable to use built-in keystore: %s", e.getMessage()));
			
		} catch (NoSuchAlgorithmException e) {
			log.warning(String.format("SSL Protocol issues detected: %s", e.getMessage()));
			
		} catch (CertificateException e) {
			log.warning(String.format("Unable to parse/open certificate: %s", e.getMessage()));
			
		}
	}
	
	/**
	 * Help
	 */
	public static void help()  {
		System.out.println("CertDownload: Downloads TLS/SSL certificates from servers.");
		System.out.println();
		System.out.println("Syntax: [java...] "+ CertDownload.class.getName() +" [-k -p <path> -P <passwd>] <host:port>");
		System.out.println("-k  Saves certificates to a keystore file. -p and -P are required.");
		System.out.println("-p  Path to save the keystore file.");
		System.out.println("-P  Password to use for the stored keystore file.");
		System.exit(1);
	}

	/**
	 * Application Entry Point.
	 * 
	 * @param args		Application arguments from the CLI.
	 */
	public static void main(String[] args) {
		port = 443;
		host = "localhost";
		storeEachCert = true;
		storeAsKeyStore = false;
		path = System.getProperty("user.dir") + System.getProperty("file.separator") + "downloaded_certs.ks";
		password = null;
		
		for(int i = 0; i < args.length; i++)  {
			if(args[i].equals("-k"))  {
				storeAsKeyStore = true;
			}else if(args[i].equals("-p"))  {
				path = args[(i + 1)];
				i++;
			}else if(args[i].equals("-P"))  {
				password = args[(i + 1)].toCharArray();
				i++;
			}else if(args[i].contains(":"))  {
				host = args[i].substring(0, args[i].lastIndexOf(':'));
				port = Integer.parseInt(args[i].substring(args[i].lastIndexOf(':') + 1));
			}else if(args[i].contains("-h"))
				help();
			
		}
		
		new Thread(new CertDownload()).start();
	}

}
