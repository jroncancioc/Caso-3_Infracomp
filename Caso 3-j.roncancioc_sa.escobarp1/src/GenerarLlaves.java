import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerarLlaves {

    public static void main(String[] args) {
        try {
            String rutaLlaves = "keys/";

            File directorio = new File(rutaLlaves);
            if (!directorio.exists()) {
                directorio.mkdirs();
            }

            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(1024);
            KeyPair parLlaves = generador.generateKeyPair();
            PrivateKey privateKey = parLlaves.getPrivate();
            PublicKey publicKey = parLlaves.getPublic();

            Path pathPrivada = Paths.get(rutaLlaves, "servidor_private.key");
            Files.write(pathPrivada, privateKey.getEncoded());

            Path pathPublica = Paths.get(rutaLlaves, "servidor_public.key");
            Files.write(pathPublica, publicKey.getEncoded());

            System.out.println("¡Llaves generadas exitosamente en la carpeta 'keys'!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
