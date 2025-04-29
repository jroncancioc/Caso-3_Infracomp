import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Base64;
import java.util.Random;

public class MedirVelocidadCifrado {

    public static void main(String[] args) throws Exception {
        medirCifradoSimetrico();
        medirCifradoAsimetrico();
    }

    private static void medirCifradoSimetrico() throws Exception {
        System.out.println("\n🔹 Medición de Cifrado Simétrico (AES-128)");

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); 
        SecretKey secretKey = keyGen.generateKey();

        byte[] datos = new byte[1024];
        new Random().nextBytes(datos);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        int numOperaciones = 10000;

        long inicio = System.nanoTime();

        for (int i = 0; i < numOperaciones; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            cipher.doFinal(datos);
        }

        long fin = System.nanoTime();

        double tiempoTotalSegundos = (fin - inicio) / 1_000_000_000.0;
        double operacionesPorSegundo = numOperaciones / tiempoTotalSegundos;

        System.out.println("Tiempo total (segundos): " + tiempoTotalSegundos);
        System.out.println("Operaciones por segundo (AES): " + operacionesPorSegundo);
    }

    private static void medirCifradoAsimetrico() throws Exception {
        System.out.println("\n🔹 Medición de Cifrado Asimétrico (RSA-2048)");

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        byte[] datos = "Mensaje corto para cifrar".getBytes();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        int numOperaciones = 1000;

        long inicio = System.nanoTime();

        for (int i = 0; i < numOperaciones; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            cipher.doFinal(datos);
        }

        long fin = System.nanoTime();

        double tiempoTotalSegundos = (fin - inicio) / 1_000_000_000.0;
        double operacionesPorSegundo = numOperaciones / tiempoTotalSegundos;

        System.out.println("Tiempo total (segundos): " + tiempoTotalSegundos);
        System.out.println("Operaciones por segundo (RSA): " + operacionesPorSegundo);
    }
}
