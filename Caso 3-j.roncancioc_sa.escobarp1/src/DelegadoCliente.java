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
            seleccionarServicio();
            recibirRespuesta(); // IP:PUERTO
            socket.close(); // ⚡️ Cerrar conexión limpia aquí
            System.out.println("Cliente> Conexión terminada tras recibir IP:Puerto.");
            // No llamar a comunicar()!
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
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());

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

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(tablaCifrada);
        byte[] ivAndCipherText = baos.toByteArray();

        if (!CryptoUtils.verifyHMAC(ivAndCipherText, hmacRecibido, hmacKey)) {
            throw new SecurityException("DelegadoCliente: Error de integridad en la tabla de servicios (HMAC no válido).");
        }

        byte[] tablaBytes = CryptoUtils.decryptAES(tablaCifrada, aesKey, iv);
        String tablaServicios = new String(tablaBytes, "UTF-8");

        System.out.println("\n*** Servicios disponibles ***");
        System.out.println(tablaServicios);
    }

    private void seleccionarServicio() throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));

        System.out.print("\nCliente> Escribe el número de servicio que deseas seleccionar: ");
        String seleccion = teclado.readLine();

        int servicioID;
        try {
            servicioID = Integer.parseInt(seleccion.trim());
        } catch (NumberFormatException e) {
            System.out.println("Cliente> Selección inválida. Se seleccionará aleatoriamente.");
            servicioID = (int) (Math.random() * 3) + 1;
        }

        System.out.println("Cliente> Servicio seleccionado: " + servicioID);

        String mensaje = String.valueOf(servicioID);

        byte[] iv = CryptoUtils.generateRandomIV();
        byte[] mensajeCifrado = CryptoUtils.encryptAES(mensaje.getBytes("UTF-8"), aesKey, iv);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(mensajeCifrado);
        byte[] ivAndCipherText = baos.toByteArray();

        byte[] hmac = CryptoUtils.generateHMAC(ivAndCipherText, hmacKey);

        out.writeInt(iv.length);
        out.write(iv);

        out.writeInt(mensajeCifrado.length);
        out.write(mensajeCifrado);

        out.writeInt(hmac.length);
        out.write(hmac);

        out.flush();

        System.out.println("Cliente> Identificador de servicio enviado al servidor.");
    }

    private void recibirRespuesta() throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());

        int ivLength = in.readInt();
        byte[] iv = new byte[ivLength];
        in.readFully(iv);

        int msgLength = in.readInt();
        byte[] respuestaCifrada = new byte[msgLength];
        in.readFully(respuestaCifrada);

        int hmacLength = in.readInt();
        byte[] hmacRecibido = new byte[hmacLength];
        in.readFully(hmacRecibido);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(respuestaCifrada);
        byte[] ivAndCipherText = baos.toByteArray();

        if (!CryptoUtils.verifyHMAC(ivAndCipherText, hmacRecibido, hmacKey)) {
            throw new SecurityException("DelegadoCliente: Error de autenticación en la respuesta del servidor (HMAC no válido).");
        }

        byte[] respuestaDescifrada = CryptoUtils.decryptAES(respuestaCifrada, aesKey, iv);
        String respuesta = new String(respuestaDescifrada, "UTF-8");

        System.out.println("\nServidor> IP y Puerto del servicio seleccionado: " + respuesta);
    }

    private void comunicar() throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());

        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));

        while (true) {
            System.out.print("Cliente> Escribe un mensaje (o 'salir'): ");
            String mensaje = teclado.readLine();

            if ("salir".equalsIgnoreCase(mensaje)) {
                System.out.println("DelegadoCliente: Cerrando conexión...");
                socket.close();
                break;
            }

            byte[] ivBytes = CryptoUtils.generateRandomIV();
            byte[] mensajeCifrado = CryptoUtils.encryptAES(mensaje.getBytes(), aesKey, ivBytes);
            byte[] hmac = CryptoUtils.generateHMAC(mensajeCifrado, hmacKey);

            out.writeInt(ivBytes.length);
            out.write(ivBytes);
            out.writeInt(mensajeCifrado.length);
            out.write(mensajeCifrado);
            out.writeInt(hmac.length);
            out.write(hmac);
            out.flush();

            byte[] respuesta = recibirMensaje();
            System.out.println("Servidor> " + new String(respuesta));
        }
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

        if (!CryptoUtils.verifyHMAC(mensajeCifrado, hmacRecibido, hmacKey)) {
            throw new SecurityException("DelegadoCliente: Error de autenticación en el mensaje recibido (HMAC no válido).");
        }

        return CryptoUtils.decryptAES(mensajeCifrado, aesKey, ivBytes);
    }
}
