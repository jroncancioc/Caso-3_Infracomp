import java.io.*;
import java.net.Socket;
import javax.crypto.*;
import java.util.Map;
import java.util.Arrays;

public class DelegadoServidor implements Runnable {

    private final Socket socket;
    private final SecretKey aesKey;
    private final SecretKey hmacKey;
    private final Map<Integer, Servicio> tablaServicios;

    public DelegadoServidor(Socket socket, SecretKey aesKey, SecretKey hmacKey, Map<Integer, Servicio> tablaServicios) {
        this.socket = socket;
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
        this.tablaServicios = tablaServicios;
    }

    @Override
    public void run() {
        DataInputStream in = null;
        DataOutputStream out = null;

        try {
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            System.out.println("DelegadoServidor: Iniciado para " + socket.getInetAddress());

            // 1️⃣ Enviar la tabla de servicios
            enviarTablaServicios(out);

            // 2️⃣ Recibir la selección del cliente (servicio ID)
            int servicioID = recibirSeleccionCliente(in);

            // 3️⃣ Buscar IP y puerto
            Servicio servicio = tablaServicios.getOrDefault(servicioID, null);

            String respuesta;
            if (servicio != null) {
                respuesta = servicio.getIp() + ":" + servicio.getPuerto();
            } else {
                respuesta = "-1:-1"; // Servicio inválido
            }

            System.out.println("DelegadoServidor: Cliente solicitó servicio " + servicioID + " -> Respuesta: " + respuesta);

            // 4️⃣ Enviar la respuesta (IP:PUERTO) al cliente
            enviarRespuesta(out, respuesta);

            // 5️⃣ Aquí puedes continuar con comunicación normal si quieres
            // Pero en esta fase ya la tarea principal se cumplió

        } catch (IOException e) {
            System.out.println("DelegadoServidor: Cliente desconectado inesperadamente.");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
                System.out.println("DelegadoServidor: Conexión cerrada.");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private void enviarTablaServicios(DataOutputStream out) throws Exception {
        StringBuilder builder = new StringBuilder();
        for (Servicio servicio : tablaServicios.values()) {
            builder.append(servicio.toString()).append("\n");
        }
        String tabla = builder.toString();
        System.out.println("DelegadoServidor: Enviando tabla de servicios...");

        byte[] iv = CryptoUtils.generateRandomIV();
        byte[] tablaCifrada = CryptoUtils.encryptAES(tabla.getBytes("UTF-8"), aesKey, iv);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(tablaCifrada);
        byte[] ivAndCipherText = baos.toByteArray();

        byte[] hmac = CryptoUtils.generateHMAC(ivAndCipherText, hmacKey);

        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(tablaCifrada.length);
        out.write(tablaCifrada);
        out.writeInt(hmac.length);
        out.write(hmac);
        out.flush();
        System.out.println("DelegadoServidor: Tabla enviada correctamente.");
    }

    private int recibirSeleccionCliente(DataInputStream in) throws Exception {
        int ivLength = in.readInt();
        byte[] iv = new byte[ivLength];
        in.readFully(iv);

        int msgLength = in.readInt();
        byte[] mensajeCifrado = new byte[msgLength];
        in.readFully(mensajeCifrado);

        int hmacLength = in.readInt();
        byte[] hmacRecibido = new byte[hmacLength];
        in.readFully(hmacRecibido);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(mensajeCifrado);
        byte[] ivAndCipherText = baos.toByteArray();

        if (!CryptoUtils.verifyHMAC(ivAndCipherText, hmacRecibido, hmacKey)) {
            throw new SecurityException("DelegadoServidor: HMAC inválido en la selección del servicio.");
        }

        byte[] mensajeDescifrado = CryptoUtils.decryptAES(mensajeCifrado, aesKey, iv);
        String servicioIDStr = new String(mensajeDescifrado, "UTF-8");

        return Integer.parseInt(servicioIDStr.trim());
    }

    private void enviarRespuesta(DataOutputStream out, String respuesta) throws Exception {
        byte[] iv = CryptoUtils.generateRandomIV();
        byte[] respuestaCifrada = CryptoUtils.encryptAES(respuesta.getBytes("UTF-8"), aesKey, iv);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(respuestaCifrada);
        byte[] ivAndCipherText = baos.toByteArray();

        byte[] hmac = CryptoUtils.generateHMAC(ivAndCipherText, hmacKey);

        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(respuestaCifrada.length);
        out.write(respuestaCifrada);
        out.writeInt(hmac.length);
        out.write(hmac);
        out.flush();
    }
}
