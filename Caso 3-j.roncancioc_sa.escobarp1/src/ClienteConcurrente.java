import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ClienteConcurrente {

    public static void main(String[] args) {
        try {
            // ⚡ Leer el número de clientes desde variable de entorno o usar 4 como default
            int numClientes = 4; // Este nùmero lo varìo dependiendo de la prueba que se quiera hacer (4, 16, 32, 64)
            String envClientes = System.getenv("NUM_CLIENTES");
            if (envClientes != null) {
                numClientes = Integer.parseInt(envClientes);
            }

            System.out.println("ClienteConcurrente: Lanzando " + numClientes + " clientes...");

            ExecutorService executor = Executors.newFixedThreadPool(numClientes);

            long tiempoInicio = System.currentTimeMillis();

            for (int i = 0; i < numClientes; i++) {
                executor.execute(new ClienteIndividual(i + 1));
            }

            executor.shutdown();
            executor.awaitTermination(10, java.util.concurrent.TimeUnit.MINUTES);

            long tiempoFin = System.currentTimeMillis();
            long duracionMs = tiempoFin - tiempoInicio;

            System.out.println("\nClienteConcurrente: Todas las consultas terminadas.");
            System.out.println("ClienteConcurrente: Tiempo total (ms): " + duracionMs);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
