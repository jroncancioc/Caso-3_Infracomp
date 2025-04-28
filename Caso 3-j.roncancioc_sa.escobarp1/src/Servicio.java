import java.io.Serializable;

public class Servicio implements Serializable {
    private static final long serialVersionUID = 1L;

    private final int id;
    private final String nombre;
    private final String ip;
    private final int puerto;

    public Servicio(int id, String nombre, String ip, int puerto) {
        this.id = id;
        this.nombre = nombre;
        this.ip = ip;
        this.puerto = puerto;
    }

    public int getId() {
        return id;
    }

    public String getNombre() {
        return nombre;
    }

    public String getIp() {
        return ip;
    }

    public int getPuerto() {
        return puerto;
    }

    @Override
    public String toString() {
        return id + ") " + nombre;
    }
}
