import java.util.Base64;

class Base64Helper {
    public static byte[] encode(final byte[] data) {
        System.out.println("Base 64 encoding of " + data.length + " bytes started");

        if (data.length <= 0) {
            throw new RuntimeException("No data to encode");
        }

        byte[] result = Base64.getEncoder().encode(data);
        System.out.println("Base 64 encoding finished");

        return result;
    }

    public static byte[] decode(final String data) {
        System.out.println("Base 64 decoding of " + data.getBytes().length + " bytes started");

        if (data.isEmpty()) {
            throw new RuntimeException("No data to decode");
        }

        byte[] result = Base64.getDecoder().decode(data);
        System.out.println("Base 64 decoding finished");

        return result;
    }

    public static byte[] decode(final byte[] data) {
        System.out.println("Base 64 decoding of " + data.length + " bytes started");

        if (data.length <= 0) {
            throw new RuntimeException("No data to decode");
        }

        byte[] result = Base64.getDecoder().decode(data);
        System.out.println("Base 64 decoding finished");

        return result;
    }
}
