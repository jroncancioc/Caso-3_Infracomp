import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;

public class ServidorPrincipal {

    private static final int PUERTO = 12345;
    private static PrivateKey servidorPrivateKey;
    private static PublicKey servidorPublicKey;

    // Tabla de servicios
    private static final Map<Integer, Servicio> tablaServicios = new HashMap<>();

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
            servidorPrivateKey = cargarLlavePrivada("C:\\Users\\LILIANA CAMACHO\\Desktop\\Uniandes\\Infracomp\\Caso-3_Infracomp\\Caso 3-j.roncancioc_sa.escobarp1\\src\\keys\\servidor_private.key");
            servidorPublicKey = cargarLlavePublica("C:\\Users\\LILIANA CAMACHO\\Desktop\\Uniandes\\Infracomp\\Caso-3_Infracomp\\Caso 3-j.roncancioc_sa.escobarp1\\src\\keys\\servidor_public.key");

            inicializarTablaServicios(); // ⚡ nuevo

            ServerSocket serverSocket = new ServerSocket(PUERTO);
            System.out.println("ServidorPrincipal: Escuchando en el puerto " + PUERTO);

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("\nServidorPrincipal: Cliente conectado desde " + socket.getInetAddress());

                if (!autenticarCliente(socket)) {
                    socket.close();
                    continue;
                }
                System.out.println("ServidorPrincipal: Cliente autenticado.");

                // DH parameters (usar estándar)
                DHParameterSpec dhSpec = new DHParameterSpec(P, G);

                enviarParametrosDH(socket, dhSpec);

                KeyPair servidorDHKeyPair = CryptoUtils.generateDHKeyPair(dhSpec);

                enviarPublicKeyDH(socket, servidorDHKeyPair.getPublic());

                PublicKey clienteDHPublicKey = recibirPublicKeyDH(socket);

                byte[] sharedSecret = CryptoUtils.computeSharedSecret(servidorDHKeyPair.getPrivate(), clienteDHPublicKey);

                byte[][] keys = CryptoUtils.deriveKeys(sharedSecret);
                SecretKey aesKey = CryptoUtils.bytesToAESKey(keys[0]);
                SecretKey hmacKey = CryptoUtils.bytesToHMACKey(keys[1]);

                System.out.println("ServidorPrincipal: Llaves de sesión derivadas exitosamente.");

                new Thread(new DelegadoServidor(socket, aesKey, hmacKey, tablaServicios)).start(); // ⚡ ahora pasa la tabla
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void inicializarTablaServicios() {
        tablaServicios.put(1, new Servicio(1, "Consulta Estado Vuelo", "127.0.0.1", 20001));
        tablaServicios.put(2, new Servicio(2, "Disponibilidad de Vuelos", "127.0.0.1", 20002));
        tablaServicios.put(3, new Servicio(3, "Costo del Vuelo", "127.0.0.1", 20003));
    }

    private static boolean autenticarCliente(Socket socket) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        String mensaje = in.readUTF();
        if (!"HELLO".equals(mensaje)) {
            System.out.println("ServidorPrincipal: Mensaje inesperado, autenticación fallida.");
            out.writeUTF("ERROR");
            return false;
        }

        System.out.println("ServidorPrincipal: HELLO recibido.");

        byte[] reto = CryptoUtils.generarBytesAleatorios(32);

        out.writeInt(reto.length);
        out.write(reto);
        out.flush();

        int longitud = in.readInt();
        byte[] retoCifrado = new byte[longitud];
        in.readFully(retoCifrado);

        byte[] retoDescifrado = CryptoUtils.decryptRSA(retoCifrado, servidorPrivateKey);

        if (MessageDigest.isEqual(reto, retoDescifrado)) {
            out.writeUTF("OK");
            return true;
        } else {
            out.writeUTF("ERROR");
            return false;
        }
    }

    private static void enviarParametrosDH(Socket socket, DHParameterSpec dhSpec) throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        byte[] pBytes = dhSpec.getP().toByteArray();
        byte[] gBytes = dhSpec.getG().toByteArray();

        out.writeInt(pBytes.length);
        out.write(pBytes);
        out.writeInt(gBytes.length);
        out.write(gBytes);
        out.flush();
    }

    private static void enviarPublicKeyDH(Socket socket, PublicKey publicKey) throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        byte[] keyBytes = publicKey.getEncoded();
        out.writeInt(keyBytes.length);
        out.write(keyBytes);
        out.flush();
    }

    private static PublicKey recibirPublicKeyDH(Socket socket) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());

        int keyLength = in.readInt();
        byte[] keyBytes = new byte[keyLength];
        in.readFully(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey cargarLlavePrivada(String ruta) throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get(ruta));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static PublicKey cargarLlavePublica(String ruta) throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get(ruta));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
