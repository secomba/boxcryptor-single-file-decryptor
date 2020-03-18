import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

class PBKDF2Helper {
    private final int iterations;
    private final byte[] salt;
    private final byte[] password;

    public PBKDF2Helper(final String pwd, final byte[] salt, final int iterations) {
        this.iterations = iterations;
        this.salt = salt;
        this.password = pwd.getBytes();
    }

    public byte[] getBytes(int count) {
        System.out.println("PBKDF2 algorithm to get " + count + " bytes started");

        if (count < 0) {
            throw new RuntimeException("Parameter 'count' can't be zero or smaller");
        }

        byte[] result;
        try {
            Charset charset = Charset.forName("UTF-8");
            CharBuffer charBuffer = charset.decode(ByteBuffer.wrap(this.password));
            char[] input = Arrays.copyOf(charBuffer.array(), this.password.length);

            KeySpec spec = new PBEKeySpec(input, this.salt, this.iterations, count * 8);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

            result = keyFactory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Could not derive bytes with PBKDF2", e);
        }

        System.out.println("PBKDF2 algorithm finished");

        return result;
    }
}
