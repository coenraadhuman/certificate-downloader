package com.github.coenraadhuman.certificatedownloader.common;

import javax.net.ssl.KeyManager;
import java.util.ArrayList;

public class KeyManagers extends ArrayList<KeyManager> {
  private static final long serialVersionUID = 1L;

  public KeyManager[] getKeyManagers() {
    if (this.size() == 0) return null;

    KeyManager[] ret = new KeyManager[this.size()];
    int i = 0;
    for (KeyManager km : this) ret[i++] = km;

    return ret;
  }
}
