import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.util.Random;

public class ClienteIterativo {

    private static final String SERVIDOR_IP = "localhost"; 
    private static final int PUERTO = 12345;
    private static PublicKey servidorPublicKey;
    private static final Random random = new Random();

    private static final BigInteger P = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD" +
        "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E" +
        "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F" +
        "A5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger G = BigInteger.valueOf(2);

    public static void main(String[] args) {
        try {
            servidorPublicKey = cargarLlavePublica("keys/servidor_public.key");

            for (int i = 1; i <= 32; i++) {
                System.out.println("\nConsulta #" + i);

                int servicioSeleccionado = random.nextInt(3) + 1; // 1, 2 o 3 aleatorio

                try (Socket socket = new Socket(SERVIDOR_IP, PUERTO)) {
                    DelegadoClienteIterativo delegado = new DelegadoClienteIterativo(socket, servidorPublicKey, P, G);
                    delegado.iniciarUnaConsulta(servicioSeleccionado);
                }

                Thread.sleep(100); // Pequeña pausa entre consultas
            }

            System.out.println("\nClienteIterativo: Terminó las 32 consultas exitosamente.");

        } catch (Exception e) {
            System.err.println("ClienteIterativo: Error general - " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static PublicKey cargarLlavePublica(String ruta) throws Exception {
        byte[] bytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(ruta));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
