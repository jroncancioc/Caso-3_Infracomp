import java.io.*;
import java.net.*;
import java.security.*;

public class Cliente {

    private static final String SERVIDOR_IP = "127.0.0.1";
    private static final int SERVIDOR_PUERTO = 5000;
    private static PublicKey servidorPublicKey;

    public static void main(String[] args) {
        try {
            cargarLlavePublica();

            Socket socket = new Socket(SERVIDOR_IP, SERVIDOR_PUERTO);
            System.out.println("[Cliente] Conectado al servidor en " + SERVIDOR_IP + ":" + SERVIDOR_PUERTO);

            InputStream entrada = socket.getInputStream();
            OutputStream salida = socket.getOutputStream();

            socket.close();
            System.out.println("[Cliente] Conexión cerrada.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void cargarLlavePublica() throws Exception {
        servidorPublicKey = (PublicKey) leerObjetoDesdeArchivo("servidor_public.key");
        System.out.println("[Cliente] Llave pública del servidor cargada exitosamente.");
    }

    private static Object leerObjetoDesdeArchivo(String nombreArchivo) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(nombreArchivo))) {
            return ois.readObject();
        }
    }
}