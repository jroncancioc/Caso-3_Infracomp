import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.util.Random;

public class ClienteIterativo {

    private static final String SERVIDOR_IP = "localhost"; // o IP del servidor
    private static final int PUERTO = 12345;
    private static PublicKey servidorPublicKey;

    // Parámetros DH estándar (RFC 3526, 1024-bit MODP Group)
    private static final BigInteger P = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD" +
        "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E" +
        "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F" +
        "A5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger G = BigInteger.valueOf(2);

    public static void main(String[] args) {
        try {
            servidorPublicKey = cargarLlavePublica("src/keys/servidor_public.key");

            Socket socket = new Socket(SERVIDOR_IP, PUERTO);
            System.out.println("ClienteIterativo: Conectado al servidor.");

            DelegadoClienteIterativo delegado = new DelegadoClienteIterativo(socket, servidorPublicKey, P, G);

            delegado.iniciar();

        } catch (Exception e) {
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
