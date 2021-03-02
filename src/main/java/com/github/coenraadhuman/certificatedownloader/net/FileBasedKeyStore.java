package com.github.coenraadhuman.certificatedownloader.net;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;

@Slf4j
@Component
@NoArgsConstructor
public class FileBasedKeyStore extends KeyStore {
  @Getter private String path;

  public FileBasedKeyStore(File file, char[] password) {

    if (!file.exists())
      throw new RuntimeException(
          String.format("KeyStore file %s must actually exist.", file.toString()));

    this.path = file.toString();
    this.password = password;

    FileInputStream fis = null;
    try {
      this.keyStore = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
      fis = new FileInputStream(file);
      this.keyStore.load(fis, password);
      log.info("Loaded KeyStore {} successfully.", file);

    } catch (Exception e) {
      log.warn("Could not open/read from KeyStore " + file + ": " + e.getMessage());
      throw new RuntimeException(
          String.format("Could not open/read from the KeyStore %s: %s ", file, e.getMessage()));

    } finally {
      if (fis != null) {
        try {
          fis.close();
        } catch (Exception ignored) {
        }
      }
    }
  }

  public FileBasedKeyStore(String filename, char[] password) {
    this(new File(filename), password);
  }
}
