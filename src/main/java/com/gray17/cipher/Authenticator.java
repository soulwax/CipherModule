package com.gray17.cipher;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Authenticator {

    // On the server, this gets replaced by an encrypted database, but you could use this for production instead.
    // Just make sure to make it persistent then. Or keep using the cert keystore only.
    private final Map<String, UserInfo> userDatabase = new HashMap<>();

    public Authenticator() {
    }

    /**
     * The main function of this class.
     * Using protected access modifier to add another degree of access control.
     * @param userName the username provided
     * @param password the corresponding password for the username to authenticate
     * @throws NoSuchAlgorithmException for an invalid crypto algorithm chosen
     * @throws InvalidKeySpecException for an invalid key specification
     */

    protected void signUp(String userName, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String salt = getNewSalt();
        String encryptedPassword = getEncryptedPassword(password, salt);
        UserInfo user = new UserInfo();
        user.userEncryptedPassword = encryptedPassword;
        user.userName = userName;
        user.userSalt = salt;
        saveUser(user);
    }

    protected boolean authenticateUser(String inputUser, String inputPass) throws NoSuchAlgorithmException, InvalidKeySpecException {
        UserInfo user = userDatabase.get(inputUser);
        if (user == null) {
            return false;
        } else {
            String salt = user.userSalt;
            String calculatedHash = getEncryptedPassword(inputPass, salt);
            return calculatedHash.equals(user.userEncryptedPassword);
        }
    }

    // Get a encrypted password using PBKDF2 hash algorithm
    public String getEncryptedPassword(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String algorithm = "PBKDF2WithHmacSHA1";
        int derivedKeyLength = 160; // for SHA1
        int iterations = 20000; // NIST specifies 10000

        byte[] saltBytes = Base64.getDecoder().decode(salt);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, iterations, derivedKeyLength);
        SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);

        byte[] encBytes = f.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(encBytes);
    }

    // Returns base64 encoded salt
    public String getNewSalt() throws NoSuchAlgorithmException {
        // Don't use Random!
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        // NIST recommends minimum 4 bytes. We use 8.
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private void saveUser(UserInfo user) {
        userDatabase.put(user.userName, user);
    }
}
