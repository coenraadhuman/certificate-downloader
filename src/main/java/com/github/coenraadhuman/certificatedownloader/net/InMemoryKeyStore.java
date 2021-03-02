package com.github.coenraadhuman.certificatedownloader.net;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Slf4j
@Component
public class InMemoryKeyStore extends KeyStore {

  public InMemoryKeyStore()
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    this.keyStore = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
    this.password = new char[] {'\0'};
    this.keyStore.load(null, this.password);
    log.info("Loaded in-memory keystore successfully.");
  }
}
