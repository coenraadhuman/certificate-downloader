package com.github.coenraadhuman.certificatedownloader;

import com.github.coenraadhuman.certificatedownloader.utils.CertDownload;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Objects;

@SpringBootApplication
public class CertificateDownloaderApplication {

  public static String host;
  public static Integer port;
  public static Boolean storeEachCert = true;
  public static Boolean storeAsKeyStore = false;
  public static char[] password;
  public static String path;

  public static void main(String[] args) {
    var context = SpringApplication.run(CertificateDownloaderApplication.class, args);

    for (int i = 0; i < args.length; i++) {
      if (args[i].equals("-k")) {
        storeAsKeyStore = true;
      } else if (args[i].equals("-p")) {
        path = args[(i + 1)];
        i++;
      } else if (args[i].equals("-P")) {
        password = args[(i + 1)].toCharArray();
        i++;
      } else if (args[i].contains(":")) {
        host = args[i].substring(0, args[i].lastIndexOf(':'));
        port = Integer.parseInt(args[i].substring(args[i].lastIndexOf(':') + 1));
      } else if (args[i].contains("-h")) {
        help();
      }
    }

    if (isArgumentsValid()) {
      var certDownload = context.getBean(CertDownload.class);
      new Thread(certDownload).start();
    } else {
      help();
    }
  }

  public static boolean isArgumentsValid() {
    if (Objects.isNull(host) || Objects.isNull(port)) {
       return false;
    }

    if (storeAsKeyStore.equals(true) && (Objects.isNull(path) || Objects.isNull(password))) {
      return false;
    }

    return true;
  }

  public static void help() {
    System.out.println("certificate-downloader: Downloads TLS/SSL certificates from servers.");
    System.out.println();
    System.out.format(
        "Syntax: java -jar certificate-downloader-[version] [-k -p <path> -P <passwd>] <host:port>");
    System.out.println("-k  Saves certificates to a keystore file. -p and -P are required.");
    System.out.println("-p  Path to save the keystore file.");
    System.out.println("-P  Password to use for the stored keystore file.");
    System.exit(1);
  }
}
