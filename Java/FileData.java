import jdk.nashorn.api.scripting.JSObject;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

class FileData {
    private static class HeaderData {
        public final int rawLen = 48; // always 48 bytes
        public int coreLen;
        public int corePaddingLen;
        public int ciipherPaddingLen;
    }

    private String encryptedFileKey;
    private String baseIVec;
    private String encryptedFilePath;
    private int blockSize;
    private final HeaderData headerData;
    private String outputFilePath;
    private final byte[] supportedFileVersion = {(byte) 98, (byte) 99, (byte) 48, (byte) 49};

    // appends a incrementing number to either the output path
    // or the original path if no output was given until
    // a path is found for which no file exists yet
    // CAUTION: this can break if file names are too long
    private String checkOutputFilePath(final String currentPath) {
        int postFix = 1;
        String newPath = currentPath;
        String originalPath = currentPath;
        boolean suitablePathFound = false;

        while (!suitablePathFound) {
            if (newPath.length() == 0) {
                System.out.println("Output filepath is empty, deriving it from input");

                // first, get rid of the .bc extension
                int startPos = 0;
                int endPos = this.encryptedFilePath.lastIndexOf(".");
                if (endPos == -1) {
                    break;
                }
                newPath = originalPath = this.encryptedFilePath.substring(startPos, endPos);
            }

            if (Files.exists(Paths.get(newPath))) {
                System.out.println("Output filepath '" + newPath + "' already exists, deriving a new one");

                // insert a number after the file name
                int extensionPos = originalPath.lastIndexOf(".");
                if (extensionPos == -1) {
                    break;
                }

                newPath = originalPath.substring(0, extensionPos) + " (" + String.valueOf(postFix) + ")" + originalPath.substring(extensionPos);
                ++postFix;
            } else {
                suitablePathFound = true;
                break;
            }

            System.out.println("New output filepath: " + newPath);
        }

        if (!suitablePathFound) {
            throw new RuntimeException("Could not find a usable output filepath");
        }

        return newPath;
    }

    public FileData() {
        this.headerData = new HeaderData();
    }

    // this method should ideally be implemented using a proper JSON library,
    // but for the purpose of demonstrating which infos are needed from
    // the file header the built in scripting solution should be sufficient
    public void parseHeader(final String encryptedFilePath, final String outputFilePath) {
        System.out.println("Parsing header of encrypted file: '" + encryptedFilePath + "'");

        if (!encryptedFilePath.substring(encryptedFilePath.length() - 3).equals(".bc")) {
            throw new RuntimeException("Given filepath does not have the right extension ('.bc'), please specify a Boxcryptor encrypted file");
        }

        if (!Files.isRegularFile(Paths.get(encryptedFilePath))) {
            throw new RuntimeException("Encrypted file (" + encryptedFilePath + ") can't be opened (make sure the provided path "
                    + "is correct, the file exists and you have the right to open the file)");
        }

        this.encryptedFilePath = encryptedFilePath;

        try {
            // read the first 16 bytes which contain the file version
            // and information about the length of the different file parts
            byte[] rawHeaderBytes = new byte[16];
            InputStream is = new FileInputStream(encryptedFilePath);
            is.read(rawHeaderBytes, 0, 16);

            byte[] fileVersionBytes = Arrays.copyOfRange(rawHeaderBytes, 0, 4);
            if (!Arrays.equals(fileVersionBytes, this.supportedFileVersion)) {
                throw new RuntimeException("Unknown file version found in header, aborting...");
            }

            byte[] headerCoreLenBytes = Arrays.copyOfRange(rawHeaderBytes, 4, 8);
            byte[] headerPaddingLenBytes = Arrays.copyOfRange(rawHeaderBytes, 8, 12);
            byte[] cipherPaddingLenBytes = Arrays.copyOfRange(rawHeaderBytes, 12, 16);

            int headerCoreLen = (headerCoreLenBytes[3] & 0xFF) << 24 | (headerCoreLenBytes[2] & 0xFF) << 16
                    | (headerCoreLenBytes[1] & 0xFF) << 8 | (headerCoreLenBytes[0] & 0xFF);
            int headerPaddingLen = (headerPaddingLenBytes[3] & 0xFF) << 24 | (headerPaddingLenBytes[2] & 0xFF) << 16
                    | (headerPaddingLenBytes[1] & 0xFF) << 8 | (headerPaddingLenBytes[0] & 0xFF);
            int cipherPaddingLen = (cipherPaddingLenBytes[3] & 0xFF) << 24 | (cipherPaddingLenBytes[2] & 0xFF) << 16
                    | (cipherPaddingLenBytes[1] & 0xFF) << 8 | (cipherPaddingLenBytes[0] & 0xFF);

            this.headerData.coreLen = headerCoreLen;
            this.headerData.corePaddingLen = headerPaddingLen;
            this.headerData.ciipherPaddingLen = cipherPaddingLen;

            // go to the end of the raw header and read the core header
            is.skip(this.headerData.rawLen - 16);
            byte[] coreHeaderBytes = new byte[this.headerData.coreLen];
            is.read(coreHeaderBytes, 0, this.headerData.coreLen);

            // parse the json data in core file header
            String EXTRACTOR_SCRIPT = "var parseJSON = function(raw) { " +
                    "var json = JSON.parse(raw); " +
                    "return { blockSize: json.cipher.blockSize, " +
                    "ivec: json.cipher.iv, fileKey: json.encryptedFileKeys[0].value};};";

            ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
            engine.eval(EXTRACTOR_SCRIPT);
            Invocable invocable = (Invocable) engine;
            JSObject result = (JSObject) invocable.invokeFunction("parseJSON", new String(coreHeaderBytes));

            this.blockSize = Integer.valueOf(result.getMember("blockSize").toString());
            this.baseIVec = result.getMember("ivec").toString();
            this.encryptedFileKey = result.getMember("fileKey").toString();

            this.outputFilePath = this.checkOutputFilePath(outputFilePath);
        } catch (IOException |ScriptException |NoSuchMethodException e) {
            throw new RuntimeException("Header could not be parsed", e);
        }

        System.out.println("Parsing finished");
    }

    public String getOutputFilePath() {
        return this.outputFilePath;
    }

    public String getEncryptedFileKey() {
        return this.encryptedFileKey;
    }

    public String getEncryptedFilePath() {
        return this.encryptedFilePath;
    }

    public String getBaseIVec() {
        return this.baseIVec;
    }

    public int getBlockSize() {
        return this.blockSize;
    }

    public int getHeaderLen() {
        return this.headerData.rawLen + this.headerData.coreLen + this.headerData.corePaddingLen;
    }

    public int getCipherPadding() {
        return this.headerData.ciipherPaddingLen;
    }
}
