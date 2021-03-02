package com.github.coenraadhuman.certificatedownloader.net;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

@Slf4j
@Component
public class AcceptAllX509TrustManager implements X509TrustManager {

  private final ArrayList<X509Certificate> issuers;

  public AcceptAllX509TrustManager() {
    super();
    issuers = new ArrayList<>();
  }

  /** @return the issuers */
  public ArrayList<X509Certificate> getIssuers() {
    return issuers;
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType) {

    for (X509Certificate cert : chain) {
      log.info("Downloaded/Saved {} certificate: {}", authType, cert.getSubjectDN());
      this.issuers.add(cert);
    }
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType) {

    for (X509Certificate cert : chain) {
      log.info("Downloaded/Saved {} certificate: {}", authType, cert.getSubjectDN());
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
