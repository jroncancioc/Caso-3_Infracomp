import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoUtils {

    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decryptRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static byte[] encryptAES(byte[] data, SecretKey key, byte[] ivBytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    public static byte[] decryptAES(byte[] encryptedData, SecretKey key, byte[] ivBytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(encryptedData);
    }

    public static byte[] generateRandomIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static byte[] generateHMAC(byte[] data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(data);
    }

    public static boolean verifyHMAC(byte[] data, byte[] receivedHmac, SecretKey key) throws Exception {
        byte[] expectedHmac = generateHMAC(data, key);
        return MessageDigest.isEqual(expectedHmac, receivedHmac);
    }

    public static KeyPair generateDHKeyPair(DHParameterSpec dhSpec) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(dhSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DiffieHellman"); // ⚡ Cambio aquí
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        return keyAgree.generateSecret(); // Obtenemos el byte[] crudo
    }

    public static DHParameterSpec generateDHParams() throws Exception {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        return params.getParameterSpec(DHParameterSpec.class);
    }

    public static byte[][] deriveKeys(byte[] sharedSecret) throws Exception {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);

        byte[] keyEnc = Arrays.copyOfRange(digest, 0, 32);
        byte[] keyMac = Arrays.copyOfRange(digest, 32, 64);

        return new byte[][] { keyEnc, keyMac };
    }

    public static SecretKey bytesToAESKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static SecretKey bytesToHMACKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    public static byte[] generarBytesAleatorios(int numBytes) {
        byte[] bytes = new byte[numBytes];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
