package com.github.coenraadhuman.certificatedownloader.common;

public enum KeyType {
  RSA,
  DSA;

  @Override
  public String toString() {
    return (this == RSA) ? "RSA" : "DSA";
  }
}
