import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class GenerarLlaves {

    public static void main(String[] args) {
        try {
            String rutaLlaves = "C:\\Users\\juand\\OneDrive\\Desktop\\UNIANDES\\2025-10\\INFRACOMP\\Casos\\Caso 3\\Caso-3_Infracomp\\Caso 3-j.roncancioc_sa.escobarp1\\src\\keys\\";

            File directorio = new File(rutaLlaves);
            if (!directorio.exists()) {
                directorio.mkdirs();
            }

            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(1024);
            KeyPair parLlaves = generador.generateKeyPair();
            PrivateKey privateKey = parLlaves.getPrivate();
            PublicKey publicKey = parLlaves.getPublic();

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(rutaLlaves + "servidor_private.key"))) {
                oos.writeObject(privateKey);
            }

            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(rutaLlaves + "servidor_public.key"))) {
                oos.writeObject(publicKey);
            }

            System.out.println("¡Llaves generadas exitosamente en la carpeta keys!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}