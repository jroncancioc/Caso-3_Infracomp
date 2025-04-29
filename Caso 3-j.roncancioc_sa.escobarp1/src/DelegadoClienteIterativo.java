import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

public class DelegadoClienteIterativo {

    private final Socket socket;
    private final PublicKey servidorPublicKey;
    private SecretKey aesKey;
    private SecretKey hmacKey;
    private final BigInteger p;
    private final BigInteger g;

    public DelegadoClienteIterativo(Socket socket, PublicKey servidorPublicKey, BigInteger p, BigInteger g) {
        this.socket = socket;
        this.servidorPublicKey = servidorPublicKey;
        this.p = p;
        this.g = g;
    }

    public void iniciarUnaConsulta(int servicioSeleccionado) {
        try {
            autenticarServidor();
            intercambiarLlavesDH();
            recibirTablaServicios();
            enviarSolicitud(servicioSeleccionado);
            String respuesta = recibirRespuesta();
            System.out.println("Servidor> " + respuesta);
        } catch (Exception e) {
            System.err.println("DelegadoClienteIterativo: Error en la consulta - " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
            }
        }
    }

    private void autenticarServidor() throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());

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
            throw new RuntimeException("DelegadoClienteIterativo: Falló la autenticación del servidor.");
        }
        System.out.println("DelegadoClienteIterativo: Autenticación exitosa.");
    }

    private void intercambiarLlavesDH() throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        int pLength = in.readInt();
        byte[] pBytes = new byte[pLength];
        in.readFully(pBytes);

        int gLength = in.readInt();
        byte[] gBytes = new byte[gLength];
        in.readFully(gBytes);

        BigInteger pRecibido = new BigInteger(pBytes);
        BigInteger gRecibido = new BigInteger(gBytes);

        if (!p.equals(pRecibido) || !g.equals(gRecibido)) {
            throw new RuntimeException("DelegadoClienteIterativo: Error en parámetros DH.");
        }

        DHParameterSpec dhSpec = new DHParameterSpec(p, g);
        KeyPair keyPair = CryptoUtils.generateDHKeyPair(dhSpec);

        int serverPubKeyLength = in.readInt();
        byte[] serverPubKeyBytes = new byte[serverPubKeyLength];
        in.readFully(serverPubKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey servidorDHPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyBytes));

        byte[] clientePubKeyBytes = keyPair.getPublic().getEncoded();
        out.writeInt(clientePubKeyBytes.length);
        out.write(clientePubKeyBytes);
        out.flush();

        byte[] sharedSecret = CryptoUtils.computeSharedSecret(keyPair.getPrivate(), servidorDHPublicKey);

        byte[][] keys = CryptoUtils.deriveKeys(sharedSecret);
        aesKey = CryptoUtils.bytesToAESKey(keys[0]);
        hmacKey = CryptoUtils.bytesToHMACKey(keys[1]);

        System.out.println("DelegadoClienteIterativo: Llaves de sesión derivadas.");
    }

    private void recibirTablaServicios() throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());

        int ivLength = in.readInt();
        byte[] iv = new byte[ivLength];
        in.readFully(iv);

        int tablaLength = in.readInt();
        byte[] tablaCifrada = new byte[tablaLength];
        in.readFully(tablaCifrada);

        int hmacLength = in.readInt();
        byte[] hmac = new byte[hmacLength];
        in.readFully(hmac);

        int firmaLength = in.readInt();
        byte[] firmaTabla = new byte[firmaLength];
        in.readFully(firmaTabla);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(tablaCifrada);

        if (!CryptoUtils.verifyHMAC(baos.toByteArray(), hmac, hmacKey)) {
            throw new SecurityException("DelegadoClienteIterativo: HMAC inválido en tabla de servicios.");
        }

        byte[] tablaBytes = CryptoUtils.decryptAES(tablaCifrada, aesKey, iv);
        String tabla = new String(tablaBytes, "UTF-8");

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(servidorPublicKey);
        signature.update(tabla.getBytes("UTF-8"));
        if (!signature.verify(firmaTabla)) {
            throw new SecurityException("DelegadoClienteIterativo: Firma inválida en tabla de servicios.");
        }

        System.out.println("\n*** Servicios disponibles ***\n" + tabla);
    }

    private void enviarSolicitud(int servicioSeleccionado) throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        byte[] servicioBytes = String.valueOf(servicioSeleccionado).getBytes("UTF-8");

        byte[] iv = CryptoUtils.generateRandomIV();
        byte[] mensajeCifrado = CryptoUtils.encryptAES(servicioBytes, aesKey, iv);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(mensajeCifrado);
        byte[] ivAndCipher = baos.toByteArray();

        byte[] hmac = CryptoUtils.generateHMAC(ivAndCipher, hmacKey);

        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(mensajeCifrado.length);
        out.write(mensajeCifrado);
        out.writeInt(hmac.length);
        out.write(hmac);
        out.flush();
    }

    private String recibirRespuesta() throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());

        int ivLength = in.readInt();
        byte[] iv = new byte[ivLength];
        in.readFully(iv);

        int msgLength = in.readInt();
        byte[] mensajeCifrado = new byte[msgLength];
        in.readFully(mensajeCifrado);

        int hmacLength = in.readInt();
        byte[] hmac = new byte[hmacLength];
        in.readFully(hmac);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(mensajeCifrado);

        if (!CryptoUtils.verifyHMAC(baos.toByteArray(), hmac, hmacKey)) {
            throw new SecurityException("DelegadoClienteIterativo: HMAC inválido en respuesta.");
        }

        byte[] mensajeClaro = CryptoUtils.decryptAES(mensajeCifrado, aesKey, iv);
        return new String(mensajeClaro, "UTF-8");
    }
}