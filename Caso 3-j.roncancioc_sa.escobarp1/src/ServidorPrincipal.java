import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.nio.file.*;

public class ServidorPrincipal {

    private static final int PUERTO = 12345;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    public static void main(String[] args) {
        try {
            // Cargar llaves del servidor (RUTAS RELATIVAS)
            privateKey = cargarLlavePrivada("keys/servidor_private.key");
            publicKey = cargarLlavePublica("keys/servidor_public.key");

            ServerSocket serverSocket = new ServerSocket(PUERTO);
            System.out.println("Servidor principal escuchando en el puerto " + PUERTO);

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("\nServidor: Cliente conectado desde " + socket.getInetAddress());

                try {
                    // Manejar conexión con el cliente
                    manejarCliente(socket);
                } catch (Exception e) {
                    System.out.println("Error al manejar cliente: " + e.getMessage());
                } finally {
                    socket.close();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void manejarCliente(Socket socket) throws Exception {
        // Paso 2: Procesar "HELLO" y enviar reto
        byte[] reto = procesarHello(socket);

        if (reto == null) {
            return;
        }

        // Paso 4 y 5: Verificar reto cifrado
        boolean exito = verificarReto(socket, reto);

        if (!exito) {
            System.out.println("Servidor: Cerrando conexión por fallo en verificación.");
        }
    }

    private static byte[] procesarHello(Socket socket) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        String mensaje = in.readUTF();
        if (!"HELLO".equals(mensaje)) {
            System.out.println("Servidor: Mensaje inesperado: " + mensaje);
            return null;
        }

        // Crear reto aleatorio
        byte[] reto = CryptoUtils.generateRandomBytes(32); // 32 bytes = 256 bits

        // Enviar el reto al cliente
        out.writeInt(reto.length);
        out.write(reto);
        out.flush();

        System.out.println("Servidor: Reto enviado al cliente.");
        return reto;
    }

    private static boolean verificarReto(Socket socket, byte[] retoOriginal) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        int longitud = in.readInt();
        byte[] retoCifrado = new byte[longitud];
        in.readFully(retoCifrado);

        // Descifrar reto usando llave privada
        byte[] retoDescifrado = CryptoUtils.decryptRSA(retoCifrado, privateKey);

        boolean esValido = java.util.Arrays.equals(retoOriginal, retoDescifrado);

        if (esValido) {
            out.writeUTF("OK");
            System.out.println("Servidor: Reto verificado exitosamente.");
        } else {
            out.writeUTF("ERROR");
            System.out.println("Servidor: Error en la verificación del reto.");
        }
        out.flush();
        return esValido;
    }

    private static PrivateKey cargarLlavePrivada(String rutaRelativa) throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get(rutaRelativa));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private static PublicKey cargarLlavePublica(String rutaRelativa) throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get(rutaRelativa));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}