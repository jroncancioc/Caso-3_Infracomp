import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoUtils {

    private static final SecureRandom secureRandom = new SecureRandom();

    // =========================
    // RSA Encrypt/Decrypt
    // =========================
    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // =========================
    // AES Encrypt/Decrypt
    // =========================
    public static byte[] encryptAES(byte[] data, SecretKey key, byte[] ivBytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    public static byte[] decryptAES(byte[] encryptedData, SecretKey key, byte[] ivBytes) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(encryptedData);
    }

    public static byte[] generateRandomIV() {
        byte[] iv = new byte[16]; // AES block size
        secureRandom.nextBytes(iv);
        return iv;
    }

    // =========================
    // HMAC Generate/Verify
    // =========================
    public static byte[] generateHMAC(byte[] data, SecretKey key) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data);
    }

    public static boolean verifyHMAC(byte[] data, byte[] receivedHmac, SecretKey key) throws GeneralSecurityException {
        byte[] expectedHmac = generateHMAC(data, key);
        return MessageDigest.isEqual(expectedHmac, receivedHmac);
    }

    // =========================
    // Diffie-Hellman Key Exchange
    // =========================
    public static KeyPair generateDHKeyPair(DHParameterSpec dhSpec) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(dhSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static SecretKey computeSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        return keyAgree.generateSecret("AES");
    }

    public static DHParameterSpec generateDHParams() throws GeneralSecurityException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        return params.getParameterSpec(DHParameterSpec.class);
    }

    public static byte[][] deriveKeys(byte[] sharedSecret) throws GeneralSecurityException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);

        byte[] keyEnc = Arrays.copyOfRange(digest, 0, 32);   // 256 bits for AES key
        byte[] keyMac = Arrays.copyOfRange(digest, 32, 64);  // 256 bits for HMAC key

        return new byte[][] { keyEnc, keyMac };
    }

    // =========================
    // Key Conversion Helpers
    // =========================
    public static SecretKey bytesToAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static SecretKey bytesToHMACKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    // =========================
    // Utility
    // =========================
    public static byte[] generateRandomBytes(int numBytes) {
        byte[] bytes = new byte[numBytes];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}
