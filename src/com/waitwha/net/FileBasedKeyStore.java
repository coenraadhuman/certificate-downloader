package com.waitwha.net;

import java.io.File;
import java.io.FileInputStream;

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
public class FileBasedKeyStore extends KeyStore {
	
	private String path;
	
	public FileBasedKeyStore(File file, char[] password)  {
		
		if(! file.exists())
			throw new RuntimeException("KeyStore file "+ file +" must actually exist.");
		
		this.path = file.toString();
		this.password = password;
		
		FileInputStream fis = null;
		try {
			this.keyStore = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
			fis = new FileInputStream(file);
			this.keyStore.load(fis, password);
			log.fine("Loaded KeyStore "+ file +" successfully.");
			
		}catch (Exception e) {
			//TODO -- this needs to be cleaned up.
			log.warning("Could not open/read from KeyStore "+ file +": "+ e.getMessage());
			throw new RuntimeException("Could not open/read from the KeyStore "+ file +": "+ e.getMessage());
		
		}finally{
			if(fis != null)  {
				try  {
					fis.close();
				}catch(Exception e) {}
			}
		}
	}
	
	public String getPath()  {
		return path;
	}
	
	public FileBasedKeyStore(String filename, char[] password)  {
		this(new File(filename), password);
	}
	
}