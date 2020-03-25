import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.IntStream;

class AESHelper {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static byte[] computeBlockIVec(final byte[] IVec, long seed, final byte[] key) {
        if (IVec.length <= 0 || key.length <= 0) {
            throw new RuntimeException("Base initialization vector and crypto key can't be empty");
        }

        byte[] md = new byte[8];
        for (int i = 0; i < 8; ++i) {
            md[i] = (byte) (seed & 0xff);
            seed >>= 8;
        }

        byte[] data = new byte[IVec.length + md.length];
        System.arraycopy(IVec, 0, data, 0, IVec.length);
        System.arraycopy(md, 0, data, IVec.length, md.length);

        byte[] buffer = HashHelper.ComputeSHA256HMAC(data, key, true);
        byte[] result = Arrays.copyOf(buffer, IVec.length);

        return result;
    }

    private static byte[] decryptData(final byte[] data, final byte[] cryptoKey, final byte[] IVec, Boolean isUserGeneratedData) throws UnsupportedEncodingException {
        return AESHelper.decryptData(data, cryptoKey, IVec, isUserGeneratedData, "PKCS5PADDING");
    }

    private static byte[] decryptData(final byte[] data, final byte[] cryptoKey, final byte[] IVec, Boolean isUserGeneratedData, String padding) throws UnsupportedEncodingException {
        if ((isUserGeneratedData ? data.length < 0 : data.length <= 0) || cryptoKey.length <= 0 || IVec.length <= 0) {
            throw new RuntimeException("Encrypted data, crypto key and initialization vector can't be empty");
        }

        byte[] result;
        try {
            // PKCS7 padding (https://en.wikipedia.org/wiki/PKCS) is used in case the
            // last data block is smaller than the block size used by AES (16 bytes)
            IvParameterSpec ivParamSpec = new IvParameterSpec(IVec);
            SecretKeySpec keySpec = new SecretKeySpec(cryptoKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/" + padding);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);
            result = cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | InvalidAlgorithmParameterException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Data could not be decrypted", e);
        }

        return result;
    }

    public static byte[] decryptDataPBKDF2(
            final String data,
            final String pbkdf2Password,
            final String pbkdf2Salt,
            final int pbkdf2Iterations) throws UnsupportedEncodingException {
        System.out.println("AES decryption of data started");

        if (pbkdf2Password.isEmpty() || pbkdf2Salt.isEmpty() || pbkdf2Iterations <= 0) {
            throw new RuntimeException("Password and salt for the PBKDF2 algorithm can not be empty and the iteration count must be bigger than zero");
        }

        // data and salt are base 64 encoded
        byte[] decodedPrivateKeyBytes = Base64Helper.decode(data);
        byte[] decodedSalt = Base64Helper.decode(pbkdf2Salt);

        // derive bytestream from password and salt
        // via PBKDF2 - the resulting bytes (64) are
        // two AES256 keys which will be used in further steps
        PBKDF2Helper pbkdf2 = new PBKDF2Helper(pbkdf2Password, decodedSalt, pbkdf2Iterations);
        byte[] hashBytes = pbkdf2.getBytes(64);
        int[] unsignedHashBytes = new int[64];
        for (int i = 0; i < hashBytes.length; ++i) {
            unsignedHashBytes[i] = hashBytes[i] & 0xFF;
        }

        byte[] cryptoKey = Arrays.copyOfRange(hashBytes, 0, 32);
        byte[] hmacKey = Arrays.copyOfRange(hashBytes, 32, hashBytes.length);

        // the encrypted data holds an initialization vector
        // for the AES decryption, a HMAC-SHA-256 hash to
        // verify the given input and the actual private key bytes
        byte[] IVec = Arrays.copyOfRange(decodedPrivateKeyBytes, 0, 16);
        byte[] givenHmacHash = Arrays.copyOfRange(decodedPrivateKeyBytes, 16, 48);
        byte[] privateKeyBytes = Arrays.copyOfRange(decodedPrivateKeyBytes, 48, decodedPrivateKeyBytes.length);

        // it is necessary to compute the HMAC-SHA-256 hash
        // again to make sure the private key, password, salt
        // and iteraton count weren't tampered with
        byte[] computedHmacHash = HashHelper.ComputeSHA256HMAC(privateKeyBytes, hmacKey);
        if (!Arrays.equals(computedHmacHash, givenHmacHash)) {
            throw new RuntimeException("HMAC hashes do not match, make sure you used a matching .bckey file and password");
        }

        byte[] result = AESHelper.decryptData(privateKeyBytes, cryptoKey, IVec, false);

        System.out.println("AES decryption finished");
        return result;
    }

    public static byte[] decryptFile(
            final String encryptedFilePath,
            final byte[] fileCryptoKey,
            final String baseIVec,
            final int blockSize,
            final int offset,
            final int padding) throws UnsupportedEncodingException {
        System.out.println("AES decryption of file '" + encryptedFilePath + "' started");

        if (fileCryptoKey.length <= 0 || blockSize <= 0) {
            throw new RuntimeException("Crypto key for file can't be empty and block size must be bigger than zero");
        }

        // read the encrypted file
        byte[] fileBytes;
        try {
            fileBytes = Files.readAllBytes(Paths.get(encryptedFilePath));
        } catch (IOException e) {
            throw new RuntimeException("Could not read file", e);
        }

        // IVec in file header is base 64 encoded
        byte[] decodedFileIV = Base64Helper.decode(baseIVec);

        // report initial status
        int fileSize = fileBytes.length;
        long fileSizeFivePer = Double.valueOf(Math.floor(fileSize * 0.05)).longValue();
        String byteProgress = " (0 / " + String.valueOf(fileSize) + " bytes)";
        StringBuilder routeString = new StringBuilder();
        StringBuilder spaceString = new StringBuilder();
        IntStream.range(0, 20).forEach(i -> spaceString.append(" "));
        System.out.printf("Progress: [%s]%s%n", spaceString, byteProgress);

        // decrypt each block seperately with its own initialization vector
        int blockNo = 0;
        byte[] result = new byte[fileSize - offset - padding];
        for (int byteNo = offset, nextStatusThreshold = offset, currentStep = 0; byteNo < fileSize; byteNo += blockSize, ++blockNo) {
            byte[] blockIVec = AESHelper.computeBlockIVec(decodedFileIV, blockNo, fileCryptoKey);

            // get the input data for the current block (the last block may be shorter than [blockSize] bytes)
            int end = (byteNo + blockSize >= fileSize) ? fileSize : byteNo + blockSize;
            byte[] blockInput = Arrays.copyOfRange(fileBytes, byteNo, end);

            // PKCS7 padding for the last block if a cipher padding size greater than 0 was specified in file header
            // Note: the only differnce between PKCS5 and 7 is the block size (8 and 0-255 bytes respectively),
            // Java only offers the 'PKCS5PADDING' identifier (legacy from the time only 8 byte block ciphers were available)
            String currentPadding = (end == fileSize && padding > 0) ? "PKCS5PADDING" : "NOPADDING";

            // get the decrypted data for this block ...
            byte[] decryptedBlock = AESHelper.decryptData(blockInput, fileCryptoKey, blockIVec, true, currentPadding);

            // ... and append it to the previous data
            System.arraycopy(decryptedBlock, 0, result, byteNo - offset, decryptedBlock.length);

            // report intermediate status every 5%
            if (byteNo > nextStatusThreshold) {
                int steps = byteNo / nextStatusThreshold;
                nextStatusThreshold += fileSizeFivePer * steps;

                currentStep += steps;
                byteProgress = " (" + String.valueOf(byteNo) + " / " + String.valueOf(fileSize) + " bytes)";
                routeString.setLength(0);
                IntStream.range(0, currentStep).forEach(i -> routeString.append("#"));
                spaceString.setLength(0);
                IntStream.range(0, 20 - currentStep).forEach(i -> spaceString.append(" "));
                System.out.printf("Progress: [%s%s]%s%n", routeString, spaceString, byteProgress);
            }
        }

        // newline after status report
        byteProgress = " (" + String.valueOf(fileSize) + " / " + String.valueOf(fileSize) + " bytes)";
        routeString.setLength(0);
        IntStream.range(0, 20).forEach(i -> routeString.append("#"));
        System.out.printf("Progress: [%s]%s%n", routeString, byteProgress);

        System.out.println("AES decryption of file finished");
        return result;
    }
}
