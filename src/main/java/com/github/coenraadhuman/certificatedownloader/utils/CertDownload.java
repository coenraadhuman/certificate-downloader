package com.github.coenraadhuman.certificatedownloader.utils;

import com.github.coenraadhuman.certificatedownloader.net.AcceptAllX509TrustManager;
import com.github.coenraadhuman.certificatedownloader.net.KeyStore;
import com.github.coenraadhuman.certificatedownloader.net.SSLSocketFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLSocket;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;

import static com.github.coenraadhuman.certificatedownloader.CertificateDownloaderApplication.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class CertDownload implements Runnable {

  private final SSLSocketFactory sslSocketFactory;

  /**
   * Uses the custom SSLSocketFactory, which will use an instance of AcceptAllX509TrustManager which
   * will capture all of the TLS/SSL certificates if a connection is made and the handshake
   * completes.
   */
  @Override
  public void run() {
    log.info("Connecting to {}:{}, please wait.", host, port);
    try (SSLSocket s = (SSLSocket) sslSocketFactory.createSocket(host, port)) {
      s.startHandshake();
      log.info("Connection to {}:{} completed successfully.", host, port);

      AcceptAllX509TrustManager tm =
          (AcceptAllX509TrustManager) sslSocketFactory.getTrustManagers().get(0);
      log.info("Retrieved {} certificate(s) from server.", tm.getIssuers().size());

      for (X509Certificate cert : tm.getIssuers()) {
        if (storeEachCert) {
          String filename =
              System.getProperty("user.dir")
                  + System.getProperty("file.separator")
                  + cert.getSubjectDN().toString()
                  + ".cer";
          try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(cert.getEncoded());

          } catch (IOException e) {
            log.warn("Unable to save certificate to filesystem '{}': {}", filename, e.getMessage());
          }
        }
      }

      if (storeAsKeyStore) {
        KeyStore ks = sslSocketFactory.getKeyStore();
        for (X509Certificate cert : tm.getIssuers()) ks.add(cert, UUID.randomUUID().toString());

        ks.save(path, password);
        log.info("Successfully saved keystore to {} using password '{}'.", path, password);
      }

    } catch (IOException e) {
      log.warn("Connection failed to {}:{}; {}", host, port, e.getMessage());

    } catch (KeyStoreException e) {
      log.warn("Unable to use built-in keystore: {}", e.getMessage());

    } catch (NoSuchAlgorithmException e) {
      log.warn("SSL Protocol issues detected: {}", e.getMessage());

    } catch (CertificateException e) {
      log.warn("Unable to parse/open certificate: {}", e.getMessage());
    }
  }
}
