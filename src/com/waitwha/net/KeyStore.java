package com.waitwha.net;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.logging.Logger;

import com.waitwha.logging.LogManager;
import com.waitwha.utils.StringUtils;

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
 * Custom KeyStore abstract class.
 *
 * @author Mike Duncan <mike.duncan@waitwha.com>
 * @version $Id$
 * @package com.waitwha.net
 */
public class KeyStore {
	
	public enum KeyType  {
		RSA, DSA;
		
		@Override
		public String toString()  {
			return (this == RSA) ? "RSA" : "DSA";
		}
	}
	
	protected static final Logger log = LogManager.getLogger(KeyStore.class);
	protected java.security.KeyStore keyStore;
	protected char[] password;
	
	public char[] getPassword()  {
		return this.password;
	}
	
	/**
	 * Returns the number of certificates within this store.
	 * 
	 * @return		Count of certificates in this store.
	 * @see				#java.security.KeyStore.size()
	 */
	public int getCount() {
		
		try  {
			return this.keyStore.size();
		}catch(KeyStoreException e)  {}
		
		return 0;
	}
	
	public boolean contains(X509Certificate c)  {
		if(this.getCount() == 0)
			return false;
		
		try {
			ArrayList<X509Certificate> certs = this.getCertificates();
			return certs.contains(c);
			
		}catch (KeyStoreException e) {
			log.warning("Could not search KeyStore: "+ e.getMessage());
		}
		
		return false;
	}
	
	public boolean contains(String subjectDn)  {
		if(this.getCount() == 0)
			return false;
		
		subjectDn = StringUtils.removeWhiteSpaces(subjectDn);
		
		try {
			for(X509Certificate cert : this.getCertificates())  {
				String sdn = StringUtils.removeWhiteSpaces(cert.getSubjectDN().toString());
				if(sdn.equals(subjectDn))  {
					log.fine("Found certificate for subject '"+ subjectDn +"': "+ sdn);
					return true;
				}
			}
			
		}catch (KeyStoreException e) {
			log.warning("Could not search KeyStore: "+ e.getMessage());
		}
		
		return false;
	}
	
	public X509Certificate getCertificate(String alias) throws KeyStoreException  {
		return (X509Certificate)this.keyStore.getCertificate(alias);
	}
	
	public ArrayList<X509Certificate> getCertificates() throws KeyStoreException {
		ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
		ArrayList<String> aliases = this.getAliases();
		for(String alias : aliases)
			certs.add(this.getCertificate(alias));
		
		return certs;
	}
	
	public ArrayList<X509Certificate> getCertificates(String alias) throws KeyStoreException  {
		ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
		ArrayList<String> aliases = this.getAliases();
		for(String a : aliases)
			if(a.equals(alias))
				certs.add(this.getCertificate(alias));
		
		return certs;
	}
	
	public ArrayList<X509Certificate> getCertificatesBySubject(String subjectDn)  {
		ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
		subjectDn = StringUtils.removeWhiteSpaces(subjectDn);
		try {
			for(X509Certificate c : this.getCertificates())  {
				String sdn = StringUtils.removeWhiteSpaces(c.getSubjectDN().toString());
				if(sdn.equals(subjectDn))
					certs.add(c);
			
			}
			
		}catch(KeyStoreException e) {
			log.warning("Could not get certificates by subject '"+ subjectDn +"': "+ 
					e.getMessage());
		}
		
		return certs;
	}
	
	public ArrayList<String> getAliases() throws KeyStoreException {
		ArrayList<String> aliases = new ArrayList<String>();
		Enumeration<String> e = this.keyStore.aliases();
		try  {
			while(e.hasMoreElements())
				aliases.add(e.nextElement());
			
		}catch(Exception ex) {}
		
		return aliases;
	}
	
	public String getAlias(X509Certificate c) throws KeyStoreException  {
		for(String alias : this.getAliases())  {
			if(this.getCertificate(alias) == c)
				return alias;
			
		}
		
		return null;
	}
	
	public boolean add(X509Certificate c, String alias) {
		try {
			this.keyStore.setCertificateEntry(alias, c);
			log.fine("Added certificate '"+ c.getSubjectDN() +"' to KeyStore successfully.");
			return true;
			
		}catch (KeyStoreException e) {
			log.warning("Could not add certificate '"+ c.getSubjectDN() +"' to KeyStore: "+ 
					e.getMessage());
		}
		
		return false;
	}
	
	public boolean remove(X509Certificate c)  {
		return false; //TODO
	}

	/**
	 * Returns java.security.KeyStore value for member <i>store</i>.
	 *  
	 * @return the store
	 */
	public java.security.KeyStore getStore() {
		return this.keyStore;
	}
	
	public PrivateKey getPrivateKey(String alias, char[] password) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException  {
		return (PrivateKey)this.keyStore.getKey(alias, password);
	}
	
	/**
	 * What can I say? It saves the KeyStore back to disk using the memory stored 
	 * password and file location. Yeah, prolly not all that safe, so protect yo
	 * borders. 
	 *
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @see #getPath()
	 * @see #getPassword()
	 */
	public synchronized final void save(String path, char[] password) 
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException  {
		
		FileOutputStream fos = null;
		try  {
			fos = new FileOutputStream(path);
			this.keyStore.store(fos, password);
			log.fine("Successfully saved KeyStore to disk: "+ path);
		
		}catch(IOException e)  {
			log.warning("Could not save KeyStore to "+ path +": "+ 
					e.getMessage());
		
		}finally{
			if(fos != null)  {
				try  {
					fos.close();
				}catch(Exception e) {}
			}
		}
		
	}
	
	public static final KeyStore getInstance(String filename, char[] password)  {
		return new FileBasedKeyStore(filename, password);
	}
	
	public static final KeyStore getInstance() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException  {
		return new InMemoryKeyStore();
	}

}
