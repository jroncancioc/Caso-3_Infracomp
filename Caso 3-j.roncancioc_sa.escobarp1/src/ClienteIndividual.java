import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

public class ClienteIndividual implements Runnable {

    private final int id;
    private static final String SERVIDOR_IP = "localhost";
    private static final int PUERTO = 12345;

    // Parámetros DH estándar
    private static final BigInteger P = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD" +
        "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E" +
        "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F" +
        "A5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16);
    private static final BigInteger G = BigInteger.valueOf(2);

    public ClienteIndividual(int id) {
        this.id = id;
    }

    @Override
    public void run() {
        try (Socket socket = new Socket(SERVIDOR_IP, PUERTO)) {
            System.out.println("Cliente #" + id + ": Conectado al servidor.");

            PublicKey servidorPublicKey = cargarLlavePublica();

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            autenticar(out, in, servidorPublicKey);
            SecretKey[] claves = intercambioDiffieHellman(out, in);
            SecretKey aesKey = claves[0];
            SecretKey hmacKey = claves[1];

            recibirTablaServicios(in, aesKey, hmacKey, servidorPublicKey);
            seleccionarServicio(out, in, aesKey, hmacKey);

            System.out.println("Cliente #" + id + ": Consulta finalizada exitosamente.\n");

        } catch (Exception e) {
            System.out.println("Cliente #" + id + ": Error durante ejecución.");
            e.printStackTrace();
        }
    }

    private void autenticar(DataOutputStream out, DataInputStream in, PublicKey servidorPublicKey) throws Exception {
        out.writeUTF("HELLO");
        out.flush();

        int retoLength = in.readInt();
        byte[] reto = new byte[retoLength];
        in.readFully(reto);

        byte[] retoCifrado = CryptoUtils.encryptRSA(reto, servidorPublicKey);

        out.writeInt(retoCifrado.length);
        out.write(retoCifrado);
        out.flush();

        String respuesta = in.readUTF();
        if (!"OK".equals(respuesta)) {
            throw new RuntimeException("Cliente #" + id + ": Falló la autenticación.");
        }
    }

    private SecretKey[] intercambioDiffieHellman(DataOutputStream out, DataInputStream in) throws Exception {
        int pLength = in.readInt();
        byte[] pBytes = new byte[pLength];
        in.readFully(pBytes);

        int gLength = in.readInt();
        byte[] gBytes = new byte[gLength];
        in.readFully(gBytes);

        BigInteger pRecibido = new BigInteger(pBytes);
        BigInteger gRecibido = new BigInteger(gBytes);

        if (!P.equals(pRecibido) || !G.equals(gRecibido)) {
            throw new RuntimeException("Cliente #" + id + ": Error en parámetros DH.");
        }

        DHParameterSpec dhSpec = new DHParameterSpec(P, G);
        KeyPair keyPair = CryptoUtils.generateDHKeyPair(dhSpec);

        int serverPubKeyLength = in.readInt();
        byte[] serverPubKeyBytes = new byte[serverPubKeyLength];
        in.readFully(serverPubKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyBytes));

        byte[] pubKeyBytes = keyPair.getPublic().getEncoded();
        out.writeInt(pubKeyBytes.length);
        out.write(pubKeyBytes);
        out.flush();

        byte[] sharedSecret = CryptoUtils.computeSharedSecret(keyPair.getPrivate(), serverPublicKey);

        byte[][] keys = CryptoUtils.deriveKeys(sharedSecret);
        return new SecretKey[]{ CryptoUtils.bytesToAESKey(keys[0]), CryptoUtils.bytesToHMACKey(keys[1]) };
    }

    private void recibirTablaServicios(DataInputStream in, SecretKey aesKey, SecretKey hmacKey, PublicKey servidorPublicKey) throws Exception {
        int ivLength = in.readInt();
        byte[] iv = new byte[ivLength];
        in.readFully(iv);

        int tablaLength = in.readInt();
        byte[] tablaCifrada = new byte[tablaLength];
        in.readFully(tablaCifrada);

        int hmacLength = in.readInt();
        byte[] hmacRecibido = new byte[hmacLength];
        in.readFully(hmacRecibido);

        int firmaLength = in.readInt();
        byte[] firma = new byte[firmaLength];
        in.readFully(firma);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(tablaCifrada);
        byte[] ivAndCipher = baos.toByteArray();

        if (!CryptoUtils.verifyHMAC(ivAndCipher, hmacRecibido, hmacKey)) {
            throw new SecurityException("Cliente #" + id + ": Error de integridad en la tabla.");
        }

        byte[] tablaDescifrada = CryptoUtils.decryptAES(tablaCifrada, aesKey, iv);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(servidorPublicKey);
        signature.update(tablaDescifrada);

        if (!signature.verify(firma)) {
            throw new SecurityException("Cliente #" + id + ": Firma inválida en la tabla de servicios.");
        }

        String tablaServicios = new String(tablaDescifrada, "UTF-8");
        System.out.println("\nCliente #" + id + ": Servicios disponibles:");
        System.out.println(tablaServicios);
    }

    private void seleccionarServicio(DataOutputStream out, DataInputStream in, SecretKey aesKey, SecretKey hmacKey) throws Exception {
        int idServicio = (int) (Math.random() * 3) + 1; // Selección aleatoria entre 1 y 3
        String servicioStr = String.valueOf(idServicio);

        byte[] iv = CryptoUtils.generateRandomIV();
        byte[] servicioCifrado = CryptoUtils.encryptAES(servicioStr.getBytes("UTF-8"), aesKey, iv);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(servicioCifrado);
        byte[] ivAndCipher = baos.toByteArray();

        byte[] hmac = CryptoUtils.generateHMAC(ivAndCipher, hmacKey);

        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(servicioCifrado.length);
        out.write(servicioCifrado);
        out.writeInt(hmac.length);
        out.write(hmac);
        out.flush();

        // Recibir respuesta
        int ivRespLength = in.readInt();
        byte[] ivResp = new byte[ivRespLength];
        in.readFully(ivResp);

        int respLength = in.readInt();
        byte[] respuestaCifrada = new byte[respLength];
        in.readFully(respuestaCifrada);

        int hmacRespLength = in.readInt();
        byte[] hmacResp = new byte[hmacRespLength];
        in.readFully(hmacResp);

        ByteArrayOutputStream baosResp = new ByteArrayOutputStream();
        baosResp.write(ivResp);
        baosResp.write(respuestaCifrada);
        byte[] ivAndResp = baosResp.toByteArray();

        if (!CryptoUtils.verifyHMAC(ivAndResp, hmacResp, hmacKey)) {
            throw new SecurityException("Cliente #" + id + ": Error de integridad en la respuesta del servidor.");
        }

        byte[] respuestaBytes = CryptoUtils.decryptAES(respuestaCifrada, aesKey, ivResp);
        String respuesta = new String(respuestaBytes, "UTF-8");

        System.out.println("Cliente #" + id + ": IP y Puerto del servicio seleccionado: " + respuesta);
    }

    private static PublicKey cargarLlavePublica() throws Exception {
        String ruta = new File("keys/servidor_public.key").getAbsolutePath();  // ⚡ agrega src/
        byte[] bytes = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(ruta));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
