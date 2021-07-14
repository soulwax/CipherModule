package com.gray17.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Scanner;

// FOR REFERENCE:
// Ref vs Result: Important Note: Maven args ignores "" whether provided by args or not
// "Hello how are you"

// SHA-256:
// 2953d33828c395aebe8225236ba4e23fa75e6f13bd881b9056a3295cbd64d3
// 2953d33828c395aebe8225236ba4e23fa75e6f13bd881b9056a3295cbd64d3
// MD5:
// 512a1a753426d540b1d5101154279
// 512a1a753426d540b1d5101154279
// SHA-1:
// a77b25143e5db8fc8447970b8e04bc917793b

public class CryptoMain {

    private static SafeStore safeStore;
    private static Authenticator authenticator;
    /** args: 0: [algorithm] 1...2...n: [message to digest] **/
    public static void main(String[] args) throws Exception {
        // Reading data from user
        String message;
        String algorithm = "";
        String password = "changeit";
        if(args.length == 0) {
            String userName = "admin";
            String passArgs = "password";
            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter the message");
            message = scanner.nextLine();

            authenticator.signUp(userName, passArgs);

            System.out.println("Please enter username:");
            String inputUser = scanner.nextLine();

            System.out.println("Please enter password:");
            String inputPass = scanner.nextLine();

            boolean status = authenticator.authenticateUser(inputUser, inputPass);
            if (status) {
                System.out.println("Logged in!");
            } else {
                System.out.println("Sorry, wrong username/password");
            }
            scanner.close();
            algorithm = scanner.nextLine();
        } else {
            algorithm += args[0];
            StringBuilder argsAppended = new StringBuilder();
            for(int i = 1; i < args.length; i++) {
                argsAppended.append(args[i]);
                if(i == (args.length-1)) break;
                argsAppended.append(" ");
            }
            message = argsAppended.toString();
            System.out.println("Message from Arguments: " + message);
        }

        /**
         * A hash function is useful. It's a mathematical function converting
         * one numerical value into another compressed value.
         * [value/message with arbitrary length] ===hash-function===> [message digest]
         * Java provides a class named MessageDigest which belongs to the package java.security.
         * This class supports algorithms such as:
         * SHA-1, SHA 256, MD5
         * algorithms to convert an arbitrary length message to a message digest.
         */

        //  The actual MessageDigest Object
        MessageDigest md = MessageDigest.getInstance(algorithm);

        // Passing data to the created MessageDigest Object
        md.update(message.getBytes());
        byte[] digest = md.digest();
        System.out.println("Digest result: " + Arrays.toString(digest));

        // Converting the byte array in to HexString format
        StringBuffer hexString = new StringBuffer();

        for (byte b : digest) {
            hexString.append(Integer.toHexString(0xFF & b));
        }
        System.out.println("Hex format of the digest : " + hexString);

        /**
         *MAC (Message Authentication Code)
         * algorithm is a symmetric key cryptographic
         * technique to provide message authentication.
         * For establishing MAC process, the sender and receiver share a symmetric key K.
         *
         * Essentially, a MAC is an encrypted checksum generated on the underlying message
         * that is sent along with a message to ensure message authentication.
         **/

        /**The KeyGenerator class provides getInstance() method which accepts a String variable representing the
         * equired key-generating algorithm and returns a KeyGenerator object that generates secret keys.*/
        // Creating a Key Generator Object
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");


        /**The SecureRandom class of the java.Security package provides a strong random number generator which is used
         *  to generate random numbers in Java. Instantiate this class as shown below. **/
        //Creating a SecureRandom object
        SecureRandom secRandom = new SecureRandom();

        /**The KeyGenerator class provides a method named init() this method accepts the SecureRandom object and
         * initializes the current KeyGenerator.*/
        System.out.println("Secure Random Object: " + secRandom);
        //Init the keygen with the previous secure random number
        keyGen.init(secRandom);

        //Generate actual key
        Key key = keyGen.generateKey();

        //Creating a Mac object
        Mac mac = Mac.getInstance("HmacSHA256");

        /**The init() method of the Mac class accepts an Key object and initializes the current Mac object using the given key.*/
        //Initializing the Mac object
        mac.init(key);

        //Computing the Mac
        byte[] bytes = message.getBytes();
        byte[] macResult = mac.doFinal(bytes);

        String macResultString = new String(macResult); //Quick reminder: turn bytes into a string again
        System.out.println("Mac result:");
        System.out.println(macResultString);

        // Creating new Log File (if not existing)
        String logFileName = "Encryption-Results.txt";


        //Write results
        writeEncryptionResults(logFileName, macResult);

        //Init Java Certificate Storage Unit with default pass "changeit"

        // TODO: ***WARNING*** NOT FOR PRODUCTION USE!
        CryptoMain.initSafeStore("changeit");
    }

    private static void writeEncryptionResults(String fileName, byte[] results) {
        writeEncryptionResults(fileName, new String(results));
    }

    private static void writeEncryptionResults(String fileName, String results) {
        File logFile = null;
        try {
            logFile = new File(fileName);
            if(logFile.createNewFile()) {
                System.out.println("Created new Log File: " + logFile.getName() + " - Path: " + logFile.getPath());
            } else {
                System.out.println("Log file already exists, skipping creation...");
            }
        } catch (IOException e) {
            System.out.println("An error occurred while trying to create a log file.");
            e.printStackTrace();
        }

        // Writing encryption results
        try {
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(logFile, true));
            bufferedWriter.append(results);
            bufferedWriter.newLine();
            bufferedWriter.close();
            System.out.println("Successfully logged result");
        } catch (IOException e) {
            System.out.println("An error occurred while trying to write to the log file.");
            e.printStackTrace();
        }
    }

    /**
     * A cryptosystem is an implementation of cryptographic techniques and their accompanying infrastructure to
     * provide information security services. A cryptosystem is also referred to as a cipher system.
     *
     * The various components of a basic cryptosystem are:
     *
     * Plaintext
     * Encryption Algorithm
     * Ciphertext
     * Decryption Algorithm
     * Encryption Key
     * Decryption Key
     *
     * Where:
     * *Encryption Key* is a value that is known to the sender.
     * The sender inputs the encryption key into the encryption algorithm along
     * with the plaintext in order to compute the cipher text.
     *
     * *Decryption Key* is a value that is known to the receiver.
     * The decryption key is related to the encryption key, but is not always identical to it.
     * The receiver inputs the decryption key into the decryption algorithm
     * along with the cipher text in order to compute the plaintext.
     *
     * Fundamentally there are two different keys/crypto systems
     *
     * Symmetric: Encryption and Decryption are identical. Examples: DES, 3DES, IDEA, BLOWFISH
     * Asymmetric: Different keys, but mathematically related
     * hence, retrieving the plaintext by decrypting cipher text is feasible
     * */

    private static void initSafeStore(String plainTextPass) {
        try {
            CryptoMain.safeStore = new SafeStore();
        } catch (KeyStoreException e) {
            System.out.println("Your SafeStore object could not be initialized. Stack Trace for further information following...");
            e.printStackTrace();
        }

        try {
            CryptoMain.safeStore.initSafeStore(plainTextPass);
        } catch (IOException e) {
            System.out.println("Could not write certs to storage. Check your write permissions and the following stack trace...");
            e.printStackTrace();
        } catch (CertificateException e) {
            System.out.println("Sorry, your cert isn't valid, try again.");
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Invalid Algorithm was used. See stack trace for further information...");
            e.printStackTrace();
        } catch (KeyStoreException e) {
            System.out.println("Your key couldn't be stored. See stack trace for further information...");
            e.printStackTrace();
        } finally {
            System.out.println("SafeStore Initialized successfully!");
        }
    }
}

