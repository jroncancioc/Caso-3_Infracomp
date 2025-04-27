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
            // Guardar las llaves en carpeta "keys" dentro del proyecto
            String rutaLlaves = "keys/";

            // Crear la carpeta si no existe
            File directorio = new File(rutaLlaves);
            if (!directorio.exists()) {
                directorio.mkdirs();
            }

            // Generar el par de llaves RSA
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(1024);
            KeyPair parLlaves = generador.generateKeyPair();
            PrivateKey privateKey = parLlaves.getPrivate();
            PublicKey publicKey = parLlaves.getPublic();

            // Guardar la llave privada (PKCS#8)
            Path pathPrivada = Paths.get(rutaLlaves, "servidor_private.key");
            Files.write(pathPrivada, privateKey.getEncoded());

            // Guardar la llave pública (X.509)
            Path pathPublica = Paths.get(rutaLlaves, "servidor_public.key");
            Files.write(pathPublica, publicKey.getEncoded());

            System.out.println("¡Llaves generadas exitosamente en la carpeta 'keys'!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
