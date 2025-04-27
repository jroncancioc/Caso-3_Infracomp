import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.nio.file.*;

public class Cliente {

    private static final String SERVIDOR_IP = "localhost"; // o IP del servidor
    private static final int PUERTO = 12345;
    private static PublicKey servidorPublicKey;

    public static void main(String[] args) {
        try {
            // Cargar la llave pública del servidor
            servidorPublicKey = cargarLlavePublica("src/keys/servidor_public.key");

            Socket socket = new Socket(SERVIDOR_IP, PUERTO);
            System.out.println("Cliente: Conectado al servidor.");

            // Paso 1: Enviar HELLO
            enviarHello(socket);

            // Paso 3: Procesar el reto
            procesarReto(socket);

            // Paso 6: Recibir confirmación
            boolean exito = recibirConfirmacion(socket);

            if (exito) {
                System.out.println("Cliente: Autenticación exitosa. Continuar protocolo...");
                // Aquí seguiríamos con Diffie-Hellman (pasos siguientes)
            } else {
                System.out.println("Cliente: Error de autenticación.");
            }

            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void enviarHello(Socket socket) throws Exception {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        out.writeUTF("HELLO");
        out.flush();
        System.out.println("Cliente: Enviado HELLO.");
    }

    private static void procesarReto(Socket socket) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        int longitud = in.readInt();
        byte[] reto = new byte[longitud];
        in.readFully(reto);

        // Cifrar el reto
        byte[] retoCifrado = CryptoUtils.encryptRSA(reto, servidorPublicKey);

        // Enviar reto cifrado
        out.writeInt(retoCifrado.length);
        out.write(retoCifrado);
        out.flush();

        System.out.println("Cliente: Reto cifrado enviado.");
    }

    private static boolean recibirConfirmacion(Socket socket) throws Exception {
        DataInputStream in = new DataInputStream(socket.getInputStream());

        String respuesta = in.readUTF();
        System.out.println("Cliente: Respuesta del servidor: " + respuesta);

        return "OK".equals(respuesta);
    }

    private static PublicKey cargarLlavePublica(String ruta) throws Exception {
        byte[] bytes = Files.readAllBytes(Paths.get(ruta));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}