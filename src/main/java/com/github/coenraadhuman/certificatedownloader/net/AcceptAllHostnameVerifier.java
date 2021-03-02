package com.github.coenraadhuman.certificatedownloader.net;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

@Slf4j
@Component
public class AcceptAllHostnameVerifier implements HostnameVerifier {

  /** @see HostnameVerifier#verify(String, SSLSession) */
  @Override
  public boolean verify(String hostname, SSLSession session) {
    log.info(
        "{}.verify(): Verified (without check) hostname {} for peer host {}.",
        this.getClass().getName(),
        hostname,
        session.getPeerHost());
    return true;
  }
}
