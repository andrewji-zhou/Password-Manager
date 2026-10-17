package passwordmanager.model;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;


public class PasswordModel {
    private ObservableList<Password> passwords = FXCollections.observableArrayList();

    static private File passwordFile = new File("passwords.txt");
    static private String separator = "\t";

    static private String passwordFilePassword = "";
    static private byte [] passwordFileKey;
    static private byte [] passwordFileSalt;

    private static final int keyLength = 256;
    private static final int iterations = 600000;
    private static final String algo = "AES/GCM/NoPadding";
    private static final int ivLength = 12;
    private static final int tagLength = 128;

    private static String verifyString = "Cookies";

    // Lets tests point the model at a temporary file
    static void useFile(File file) {
        passwordFile = file;
        passwordFileKey = null;
        passwordFileSalt = null;
    }

    private void loadPasswords() {
        if (passwordFileKey == null || !passwordFile.exists()) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
            // skip header
            reader.readLine();

            // read the rest of the file
            String line;
            while ((line = reader.readLine()) != null) {
                // splits up the password from the salt
                String[] parts = line.split("\t");

                // ensures there is a label and password
                if (parts.length == 2) {
                    String encryptedLabel = parts[0];
                    String encryptedPwd = parts[1];

                    //decrypt
                    String label = decryptPassword(passwordFileKey, encryptedLabel);
                    String decryptedPwd = decryptPassword(passwordFileKey, encryptedPwd);

                    // add to the list
                    passwords.add(new Password(label, decryptedPwd));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public PasswordModel() {
        loadPasswords();
    }

    static public boolean passwordFileExists() {
        return passwordFile.exists();
    }

    static public void initializePasswordFile(String password) throws IOException {
        passwordFile.createNewFile();
        try {
            byte[] salt = generateSalt();
            byte[] key = generateKey(password, salt);
            String token = encryptPassword(key, verifyString);
            String saltString = Base64.getEncoder().encodeToString(salt);
            try (PrintWriter writer = new PrintWriter(passwordFile)) {
                writer.println(saltString + "\t" + token);
            }
            // save in memory
            passwordFileSalt = salt;
            passwordFileKey = key;
        } catch (Exception e) {
            throw new IOException("Could not initialize password file", e);
        }
    }

    static public boolean verifyPassword(String password) {
        passwordFilePassword = password; // DO NOT CHANGE
        try {
            // reads the header of the password file
            String header;
            try (BufferedReader reader = new BufferedReader(new FileReader(passwordFile))) {
                header = reader.readLine();
            }

            // separates it into the salt and token
            String[] parts = header.split("\t");
            String base64Salt = parts[0];
            String encryptedToken = parts[1];

            byte[] saltBytes = Base64.getDecoder().decode(base64Salt);

            // derive key using password and salt
            byte[] key = generateKey(password, saltBytes);

            String checkToken = decryptPassword(key, encryptedToken);
            if (checkToken.equals(verifyString)) {
                passwordFileSalt = saltBytes;
                passwordFileKey = key;
                return true;
            }
        } catch (Exception e) {
            // return false if anything goes wrong
            return false;
        }

        return false;
    }

    public ObservableList<Password> getPasswords() {
        return passwords;
    }

    public void deletePassword(int index) {
        passwords.remove(index);
        savePasswordsToFile();
    }

    public void updatePassword(Password password, int index) {
        passwords.set(index, password);
        savePasswordsToFile();

    }

    public void addPassword(Password password) {
        passwords.add(password);
        savePasswordsToFile();

    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
    public static byte[] generateKey(String password, byte[] salt) throws Exception {
        // take salt and master password then run it through PBKDF2 to get 256 bit key
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    // AES-GCM with a fresh random IV per value. Stored as base64(IV + ciphertext + tag)
    public static String encryptPassword (byte[] key, String password) throws Exception {
        byte[] iv = new byte[ivLength];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(algo);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(tagLength, iv));
        byte [] encryptedData = cipher.doFinal(password.getBytes("UTF-8"));

        byte[] combined = ByteBuffer.allocate(iv.length + encryptedData.length).put(iv).put(encryptedData).array();
        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decryptPassword (byte[] key, String password) throws Exception {
        byte [] decodedData = Base64.getDecoder().decode(password);

        Cipher cipher = Cipher.getInstance(algo);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(tagLength, decodedData, 0, ivLength));
        byte [] decryptedData = cipher.doFinal(decodedData, ivLength, decodedData.length - ivLength);
        return new String(decryptedData, "UTF-8");
    }
    private void savePasswordsToFile() {
        try (PrintWriter writer = new PrintWriter(passwordFile)) {

            // rewrite the header
            String saltString = Base64.getEncoder().encodeToString(passwordFileSalt);
            String token = encryptPassword(passwordFileKey, verifyString);

            writer.println(saltString + "\t" + token);

            // loop thru passwordss
            for (Password p : passwords) {
                String label = p.getLabel();
                String plainTextPwd = p.getPassword();

                // encrypt
                String encryptedLabel = encryptPassword(passwordFileKey, label);
                String encryptedPwd = encryptPassword(passwordFileKey, plainTextPwd);

                // write to file
                writer.println(encryptedLabel + "\t" + encryptedPwd);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
