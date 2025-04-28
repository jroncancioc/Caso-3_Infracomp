import java.io.*;
import java.net.Socket;
import javax.crypto.*;
import java.util.Arrays;

public class DelegadoServidor implements Runnable {

    private final Socket socket;
    private final SecretKey aesKey;
    private final SecretKey hmacKey;

    public DelegadoServidor(Socket socket, SecretKey aesKey, SecretKey hmacKey) {
        this.socket = socket;
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
    }

    @Override
    public void run() {
        DataInputStream in = null;
        DataOutputStream out = null;

        try {
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
            System.out.println("DelegadoServidor: Iniciado para " + socket.getInetAddress());

            while (true) {
                int ivLength;
                try {
                    ivLength = in.readInt();
                } catch (EOFException eof) {
                    System.out.println("DelegadoServidor: Cliente desconectado normalmente (EOF en readInt).");
                    break;
                }

                byte[] iv = new byte[ivLength];
                in.readFully(iv);

                int cipherTextLength = in.readInt();
                byte[] cipherText = new byte[cipherTextLength];
                in.readFully(cipherText);

                int hmacLength = in.readInt();
                byte[] receivedHmac = new byte[hmacLength];
                in.readFully(receivedHmac);

                // Verificar HMAC
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(iv);
                baos.write(cipherText);
                byte[] ivAndCipherText = baos.toByteArray();

                boolean hmacOk = CryptoUtils.verifyHMAC(ivAndCipherText, receivedHmac, hmacKey);

                if (!hmacOk) {
                    System.out.println("DelegadoServidor: HMAC inválido, cerrando conexión.");
                    break;
                }

                byte[] plainText = CryptoUtils.decryptAES(cipherText, aesKey, iv);
                String mensaje = new String(plainText, "UTF-8");
                System.out.println("DelegadoServidor: Mensaje recibido -> " + mensaje);

                if (mensaje.equalsIgnoreCase("salir")) {
                    System.out.println("DelegadoServidor: Cliente solicitó cerrar conexión.");
                    break;
                }

                enviarMensaje(out, "Servidor recibió: " + mensaje);
            }

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

    private void enviarMensaje(DataOutputStream out, String mensaje) throws Exception {
        byte[] mensajeBytes = mensaje.getBytes("UTF-8");

        byte[] iv = CryptoUtils.generateRandomIV();
        byte[] cipherText = CryptoUtils.encryptAES(mensajeBytes, aesKey, iv);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(iv);
        baos.write(cipherText);
        byte[] ivAndCipherText = baos.toByteArray();

        byte[] hmac = CryptoUtils.generateHMAC(ivAndCipherText, hmacKey);

        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(cipherText.length);
        out.write(cipherText);
        out.writeInt(hmac.length);
        out.write(hmac);
        out.flush();
    }
}
