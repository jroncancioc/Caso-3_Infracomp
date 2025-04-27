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
            // Cargar llaves del servidor
            privateKey = cargarLlavePrivada("C:\\Users\\juans\\Desktop\\Juan David El Goat\\Caso-3_Infracomp\\Caso 3-j.roncancioc_sa.escobarp1\\src\\keys\\servidor_private.key");
            publicKey = cargarLlavePublica("C:\\Users\\juans\\Desktop\\Juan David El Goat\\Caso-3_Infracomp\\Caso 3-j.roncancioc_sa.escobarp1\\src\\keys\\servidor_public.key");

            ServerSocket serverSocket = new ServerSocket(PUERTO);
            System.out.println("Servidor principal escuchando en el puerto " + PUERTO);

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("\nServidor: Cliente conectado desde " + socket.getInetAddress());

                // Manejar conexión en hilo separado si quieres (por ahora en main)
                manejarCliente(socket);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void manejarCliente(Socket socket) throws Exception {
        // Paso 2: Procesar "HELLO" y enviar reto
        byte[] reto = procesarHello(socket);

        if (reto == null) {
            socket.close();
            return;
        }

        // Paso 4 y 5: Verificar reto cifrado
        boolean exito = verificarReto(socket, reto);

        if (!exito) {
            socket.close();
        }
    }

    private static byte[] procesarHello(Socket socket) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        String mensaje = in.readUTF();
        if (!"HELLO".equals(mensaje)) {
            System.out.println("Mensaje inesperado: " + mensaje);
            socket.close();
            return null;
        }

        // Crear reto aleatorio
        byte[] reto = CryptoUtils.generarBytesAleatorios(32); // 32 bytes = 256 bits

        // Enviar el reto
        out.writeInt(reto.length);
        out.write(reto);
        out.flush();

        System.out.println("Servidor: Reto enviado.");
        return reto;
    }

    private static boolean verificarReto(Socket socket, byte[] retoOriginal) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        int longitud = in.readInt();
        byte[] retoCifrado = new byte[longitud];
        in.readFully(retoCifrado);

        // Descifrar reto
        byte[] retoDescifrado = CryptoUtils.decryptRSA(retoCifrado, privateKey);

        boolean esValido = java.util.Arrays.equals(retoOriginal, retoDescifrado);

        if (esValido) {
            out.writeUTF("OK");
            System.out.println("Servidor: Reto verificado exitosamente.");
        } else {
            out.writeUTF("ERROR");
            System.out.println("Servidor: Error en verificación de reto.");
        }
        out.flush();
        return esValido;
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