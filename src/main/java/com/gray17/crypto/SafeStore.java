package com.gray17.crypto;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;


public class SafeStore {
    private final KeyStore keyStore;

    // TODO: Implement a search method to make it platform and version independent!
    public static final String PATH_TO_CA_CERTS = "C:/Program Files/Java/jre1.8.0_291/lib/security/cacerts";

    public SafeStore() throws KeyStoreException {
        keyStore = KeyStore.getInstance("JCEKS");
    }

    public void initSafeStore(String plaintextPassword) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        char[] passwd = plaintextPassword.toCharArray();
        java.io.FileInputStream fis = new FileInputStream(SafeStore.PATH_TO_CA_CERTS);
        keyStore.load(fis, passwd);

        //Creating the KeyStore.ProtectionParameter object
        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(passwd);

        //Creating SecretKey object
        SecretKey mySecretKey = new SecretKeySpec("myPassword".getBytes(), "DSA");

        //Creating SecretKeyEntry object
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(mySecretKey);
        keyStore.setEntry("secretKeyAlias", secretKeyEntry, protectionParam);

        //Storing the KeyStore object
        java.io.FileOutputStream fos = new java.io.FileOutputStream("bin.key");
        keyStore.store(fos, passwd);
        System.out.println("Your key was successfully stored in a binary format inside the file \"bin.key\"");
        System.out.println("Keep in mind that this functionality is separated from your previous login attempt and" +
                "for now a proof of concept in itself.");
    }
}
