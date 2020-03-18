import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

class RSAHelper {
    public static byte[] decryptData(final String encryptedFileKey, final byte[] decryptedPrivateKey) {
        System.out.println("RSA decryption of data has started");

        if (decryptedPrivateKey.length <= 0) {
            throw new RuntimeException("The private key used for the RSA decryption can't be empty");
        }

        // encrypted file key is base 64 encoded
        byte[] decodedFileKey = Base64Helper.decode(encryptedFileKey);

        // private key is stored in a simplified PEM format (no header / footer) and no line breaks)
        // decode it from base 64 again to get the DER encoding needed for the key spec
        byte[] privateKeyDEREncoded = Base64Helper.decode(decryptedPrivateKey);

        byte[] result;
        try {
            // create / load a PrivateKey from the DER encoded key
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyDEREncoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            Cipher decryptor = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            decryptor.init(Cipher.DECRYPT_MODE, privateKey);
            result = decryptor.doFinal(decodedFileKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException
                | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("RSA decryption unsuccessful", e);
        }

        System.out.println("RSA decryption finished");
        return result;
    }
}
