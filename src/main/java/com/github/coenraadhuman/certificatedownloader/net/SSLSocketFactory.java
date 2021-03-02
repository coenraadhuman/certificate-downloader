package com.github.coenraadhuman.certificatedownloader.net;

import com.github.coenraadhuman.certificatedownloader.common.KeyManagers;
import com.github.coenraadhuman.certificatedownloader.common.TrustManagers;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

@Slf4j
@Component
public class SSLSocketFactory extends SocketFactory {

  private static final String COULD_NOT_CREATE_SOCKET_DUE_TO_KEY_MANAGEMENT_ISSUES =
      "Could not create socket due to key management issues: {}";

  private final int defaultTimeout;
  private final String[] protocols;
  private final KeyManagers keyManagers = new KeyManagers();
  private final TrustManagers trustManagers = new TrustManagers();
  private SSLContext context;
  private boolean initContext;
  private KeyStore keyStore;

  @Autowired
  public SSLSocketFactory(
      @Value("${default.timeout}") String defaultTimeout,
      @Value("${default.protocols}") String[] protocols) {
    this.defaultTimeout = Integer.parseInt(defaultTimeout);
    this.protocols = protocols;
  }

  @PostConstruct
  public void init() {
    int i = 0;
    while (this.context == null) {
      try {
        this.context = SSLContext.getInstance(protocols[i], "SunJSSE");
        log.info(String.format("Protocol support: %s", protocols[i]));

      } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
        log.warn(
            String.format(
                "Unable to load protocol %s: %s %s",
                protocols[i], e.getClass().getName(), e.getMessage()));
      }

      i++;
      if (i >= protocols.length) {
        log.warn("Could not load any valid protocols. Connections will likely fail!  :(  ");
        break;
      }
    }

    this.initContext = false;
  }

  public KeyStore getKeyStore() {
    return this.keyStore;
  }

  public void setKeyStore(KeyStore ks) {
    try {
      KeyManagerFactory factory =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      this.keyStore = ks;
      factory.init(ks.getStore(), ks.getPassword());
      for (KeyManager m : factory.getKeyManagers()) {
        log.info("Loading KeyManager: " + m.getClass().getName());
        this.keyManagers.add(m);
      }

    } catch (Exception e) {
      log.warn("Could not set KeyStore to " + ks + ": " + e.getMessage());
    }
  }

  public void addKeyManager(KeyManager km) {
    this.keyManagers.add(km);
  }

  public KeyManagers getKeyManagers() {
    return this.keyManagers;
  }

  public void addTrustManager(TrustManager tm) {
    this.trustManagers.add(tm);
  }

  public TrustManagers getTrustManagers() {
    return this.trustManagers;
  }

  private SSLSocket createSocket(String host, int port, int timeout)
      throws KeyManagementException, IOException {
    if (!this.initContext) {

      // If there is no KeyStore, we will need to use a custom one.
      if (this.keyManagers.size() == 0) {
        try {
          this.setKeyStore(new InMemoryKeyStore());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
          log.warn("Could not load memory-based keystore: {}", e.getMessage());
        }
      }

      // If there are no trust managers present at this point, we will go ahead and accept all.
      if (this.trustManagers.size() == 0) {
        this.trustManagers.add(new AcceptAllX509TrustManager());
        log.info("No specified trust management, defaulting to accepting all certificates.");
      }

      this.context.init(
          this.keyManagers.getKeyManagers(), this.trustManagers.getTrustManagers(), null);
      log.info(
          "Initialized SSLContext: {}, {}",
          this.context.getProtocol(),
          this.context.getProvider().getClass().getName());
      this.initContext = true;
    }

    javax.net.ssl.SSLSocketFactory factory = this.context.getSocketFactory();
    SSLSocket s = (SSLSocket) factory.createSocket(host, port);
    s.setSoTimeout(timeout);
    return s;
  }

  @Override
  public Socket createSocket(String host, int port) throws IOException {
    try {
      return this.createSocket(host, port, this.defaultTimeout);

    } catch (KeyManagementException e) {
      log.warn(COULD_NOT_CREATE_SOCKET_DUE_TO_KEY_MANAGEMENT_ISSUES, e.getMessage());
    }

    return null;
  }

  @Override
  public Socket createSocket(InetAddress host, int port) throws IOException {
    try {
      return this.createSocket(host.getHostAddress(), port, this.defaultTimeout);
    } catch (KeyManagementException e) {
      log.warn(COULD_NOT_CREATE_SOCKET_DUE_TO_KEY_MANAGEMENT_ISSUES, e.getMessage());
    }

    return null;
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localhost, int localport)
      throws IOException {
    try {
      return this.createSocket(host, port, this.defaultTimeout);
    } catch (KeyManagementException e) {
      log.warn(COULD_NOT_CREATE_SOCKET_DUE_TO_KEY_MANAGEMENT_ISSUES, e.getMessage());
    }

    return null;
  }

  @Override
  public Socket createSocket(InetAddress host, int port, InetAddress localhost, int localport)
      throws IOException {
    try {
      return this.createSocket(host.getHostAddress(), port, this.defaultTimeout);
    } catch (KeyManagementException e) {
      log.warn(COULD_NOT_CREATE_SOCKET_DUE_TO_KEY_MANAGEMENT_ISSUES, e.getMessage());
    }

    return null;
  }
}
