import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class HashHelper {
    public static byte[] ComputeSHA256HMAC(final byte[] data, final byte[] key) {
        return HashHelper.ComputeSHA256HMAC(data, key, false);
    }

    public static byte[] ComputeSHA256HMAC(final byte[] data, final byte[] key, boolean silent) {
        if (!silent) {
            System.out.println("Computation of HMAC-SHA-256 hash with " + data.length + " bytes started");
        }

        if (data.length <= 0 || key.length <= 0) {
            throw new RuntimeException("No data from which to calculate hmac");
        }

        byte[] finalData;
        try {
            final String hmacType = "HmacSHA256";
            Mac sha256HMAC = Mac.getInstance(hmacType);
            SecretKeySpec keySpec = new SecretKeySpec(key, hmacType);
            sha256HMAC.init(keySpec);
            finalData = sha256HMAC.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Computation of HMAC-SHA-256 failed", e);
        }

        if (!silent) {
            System.out.println("HMAC-SHA-256 computation finished");
        }

        return finalData;
    }
}
