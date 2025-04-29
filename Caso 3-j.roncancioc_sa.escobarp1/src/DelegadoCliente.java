import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

public class DelegadoCliente {

    private final Socket socket;
    private final PublicKey servidorPublicKey;
    private SecretKey aesKey;
    private SecretKey hmacKey;
    private final BigInteger p;
    private final BigInteger g;

    public DelegadoCliente(Socket socket, PublicKey servidorPublicKey, BigInteger p, BigInteger g) {
        this.socket = socket;
        this.servidorPublicKey = servidorPublicKey;
        this.p = p;
        this.g = g;
    }

    public void iniciar() {
        try {
            autenticarServidor();
            intercambiarLlavesDH();
            recibirTablaServicios();
            comunicar();
        } catch (Exception e) {
            e.printStackTrace();
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
            throw new RuntimeException("DelegadoCliente: Falló la autenticación del servidor.");
        }
        System.out.println("DelegadoCliente: Autenticación exitosa.");
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
            throw new RuntimeException("DelegadoCliente: Error - parámetros DH no coinciden.");
        }

        DHParameterSpec dhSpec = new DHParameterSpec(p, g);
        var clienteKeyPair = CryptoUtils.generateDHKeyPair(dhSpec);

        int serverPubKeyLength = in.readInt();
        byte[] serverPubKeyBytes = new byte[serverPubKeyLength];
        in.readFully(serverPubKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey servidorDHPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyBytes));

        byte[] clientePubKeyBytes = clienteKeyPair.getPublic().getEncoded();
        out.writeInt(clientePubKeyBytes.length);
        out.write(clientePubKeyBytes);
        out.flush();

        byte[] sharedSecretBytes = CryptoUtils.computeSharedSecret(clienteKeyPair.getPrivate(), servidorDHPublicKey);

        byte[][] keys = CryptoUtils.deriveKeys(sharedSecretBytes);
        aesKey = CryptoUtils.bytesToAESKey(keys[0]);
        hmacKey = CryptoUtils.bytesToHMACKey(keys[1]);

        System.out.println("DelegadoCliente: Llaves de sesión derivadas exitosamente.");
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
        byte[] hmacRecibido = new byte[hmacLength];
        in.readFully(hmacRecibido);

        int firmaLength = in.readInt();
        byte[] firma = new byte[firmaLength];
        in.readFully(firma);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(tablaCifrada);
        byte[] ivAndCipherText = baos.toByteArray();

        if (!CryptoUtils.verifyHMAC(ivAndCipherText, hmacRecibido, hmacKey)) {
            throw new SecurityException("DelegadoCliente: Error de integridad en la tabla de servicios (HMAC no válido).");
        }

        byte[] tablaBytes = CryptoUtils.decryptAES(tablaCifrada, aesKey, iv);
        String tablaServicios = new String(tablaBytes, "UTF-8");

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(servidorPublicKey);
        signature.update(tablaBytes);

        if (!signature.verify(firma)) {
            throw new SecurityException("DelegadoCliente: Firma inválida sobre la tabla de servicios.");
        }

        System.out.println("\n*** Servicios disponibles ***");
        System.out.println(tablaServicios);
    }

    private void comunicar() throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());

        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));

        System.out.print("Cliente> Escribe el número de servicio que deseas seleccionar: ");
        String servicio = teclado.readLine().trim();

        byte[] ivBytes = CryptoUtils.generateRandomIV();
        byte[] servicioCifrado = CryptoUtils.encryptAES(servicio.getBytes("UTF-8"), aesKey, ivBytes);
        byte[] hmac = CryptoUtils.generateHMAC(concatenar(ivBytes, servicioCifrado), hmacKey);

        out.writeInt(ivBytes.length);
        out.write(ivBytes);
        out.writeInt(servicioCifrado.length);
        out.write(servicioCifrado);
        out.writeInt(hmac.length);
        out.write(hmac);
        out.flush();

        System.out.println("Cliente> Servicio seleccionado: " + servicio);
        System.out.println("Cliente> Identificador de servicio enviado al servidor.");

        byte[] respuesta = recibirMensaje();
        System.out.println("\nServidor> IP y Puerto del servicio seleccionado: " + new String(respuesta, "UTF-8"));

        System.out.println("Cliente> Conexión terminada tras recibir IP:Puerto.");
        socket.close();
    }

    private byte[] recibirMensaje() throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());

        int ivLength = in.readInt();
        byte[] ivBytes = new byte[ivLength];
        in.readFully(ivBytes);

        int msgLength = in.readInt();
        byte[] mensajeCifrado = new byte[msgLength];
        in.readFully(mensajeCifrado);

        int hmacLength = in.readInt();
        byte[] hmacRecibido = new byte[hmacLength];
        in.readFully(hmacRecibido);

        if (!CryptoUtils.verifyHMAC(concatenar(ivBytes, mensajeCifrado), hmacRecibido, hmacKey)) {
            throw new SecurityException("DelegadoCliente: Error de autenticación en el mensaje recibido (HMAC no válido).");
        }

        return CryptoUtils.decryptAES(mensajeCifrado, aesKey, ivBytes);
    }

    private byte[] concatenar(byte[] iv, byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(data);
        return baos.toByteArray();
    }
}
