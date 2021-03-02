package com.github.coenraadhuman.certificatedownloader.common;

import javax.net.ssl.TrustManager;
import java.util.ArrayList;

public class TrustManagers extends ArrayList<TrustManager> {
  private static final long serialVersionUID = 1L;

  public TrustManager[] getTrustManagers() {
    if (this.size() == 0) return null;

    TrustManager[] ret = new TrustManager[this.size()];
    int i = 0;
    for (TrustManager tm : this) ret[i++] = tm;

    return ret;
  }
}
