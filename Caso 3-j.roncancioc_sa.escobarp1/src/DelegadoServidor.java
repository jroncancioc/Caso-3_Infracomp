import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Map;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class DelegadoServidor implements Runnable {

    private final Socket socket;
    private final SecretKey aesKey;
    private final SecretKey hmacKey;
    private final Map<Integer, Servicio> tablaServicios;
    private final PrivateKey servidorPrivateKey;

    public DelegadoServidor(Socket socket, SecretKey aesKey, SecretKey hmacKey, Map<Integer, Servicio> tablaServicios, PrivateKey servidorPrivateKey) {
        this.socket = socket;
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
        this.tablaServicios = tablaServicios;
        this.servidorPrivateKey = servidorPrivateKey;
    }

    @Override
    public void run() {
        DataInputStream in = null;
        DataOutputStream out = null;

        try {
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());

            System.out.println("DelegadoServidor: Iniciado para " + socket.getInetAddress());

            enviarTablaServicios(out);

            int servicioID = recibirSeleccionCliente(in);

            Servicio servicio = tablaServicios.getOrDefault(servicioID, null);

            String respuesta;
            if (servicio != null) {
                respuesta = servicio.getIp() + ":" + servicio.getPuerto();
            } else {
                respuesta = "-1:-1"; 
            }

            System.out.println("DelegadoServidor: Cliente solicitó servicio " + servicioID + " -> Respuesta: " + respuesta);

            enviarRespuesta(out, respuesta);

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

        long inicioFirma = System.nanoTime();
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(servidorPrivateKey);
        firma.update(tabla.getBytes("UTF-8"));
        byte[] firmaTabla = firma.sign();
        long finFirma = System.nanoTime();
        long tiempoFirmaMs = (finFirma - inicioFirma) / 1_000_000;
        System.out.println("Tiempo de firma de tabla (ms): " + tiempoFirmaMs);

        long inicioCifrado = System.nanoTime();
        byte[] iv = CryptoUtils.generateRandomIV();
        byte[] tablaCifrada = CryptoUtils.encryptAES(tabla.getBytes("UTF-8"), aesKey, iv);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(tablaCifrada);
        byte[] ivAndCipherText = baos.toByteArray();

        byte[] hmac = CryptoUtils.generateHMAC(ivAndCipherText, hmacKey);
        long finCifrado = System.nanoTime();
        long tiempoCifradoMs = (finCifrado - inicioCifrado) / 1_000_000;
        System.out.println("Tiempo de cifrado de tabla (ms): " + tiempoCifradoMs);

        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(tablaCifrada.length);
        out.write(tablaCifrada);
        out.writeInt(hmac.length);
        out.write(hmac);

        out.writeInt(firmaTabla.length);
        out.write(firmaTabla);

        out.flush();
        System.out.println("DelegadoServidor: Tabla y firma enviadas correctamente.");
    }

    private int recibirSeleccionCliente(DataInputStream in) throws Exception {
        long inicioVerificacion = System.nanoTime();

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

        long finVerificacion = System.nanoTime();
        long tiempoVerificacionMs = (finVerificacion - inicioVerificacion) / 1_000_000;
        System.out.println("Tiempo de verificación de consulta (ms): " + tiempoVerificacionMs);

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
