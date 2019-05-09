import jdk.nashorn.api.scripting.JSObject;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.InputMismatchException;

class AccountData {
    private String bcKeyFilePath;
    private String password;
    private String encryptedPrivateKey;
    private String pbkdf2Salt;
    private int pbkdf2Iterations;

    // this method should ideally be implemented using a proper JSON library,
    // but for the purpose of demonstrating which infos are needed from
    // the file header the built in scripting solution should be sufficient
    public void parseBCKeyFile(final String keyFilePath) {
        System.out.println("Parsing .bckey file: '" + keyFilePath + "'");

        if (!keyFilePath.substring(keyFilePath.length() - 6).equals(".bckey")) {
            throw new RuntimeException("Given filepath does not have the right extension ('.bckey'), please specify a Boxcryptor key file");
        }

        if (!Files.isRegularFile(Paths.get(keyFilePath))) {
            throw new RuntimeException("Encrypted file (" + keyFilePath + ") can't be opened (make sure the provided path "
                    + "is correct, the file exists and you have the right to open the file)");
        }

        this.bcKeyFilePath = keyFilePath;

        try {
            byte[] keyFileData = Files.readAllBytes(Paths.get(keyFilePath));

            // parse the json data in .bckey-file
            String EXTRACTOR_SCRIPT = "var parseJSON = function(raw) { " +
                            "var json = JSON.parse(raw); " +
                            "return { privateKey: json.users[0].privateKey, " +
                            "salt: json.users[0].salt, iterations: json.users[0].kdfIterations};};";

            ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
            engine.eval(EXTRACTOR_SCRIPT);
            Invocable invocable = (Invocable) engine;
            JSObject result = (JSObject) invocable.invokeFunction("parseJSON", new String(keyFileData));

            this.encryptedPrivateKey = result.getMember("privateKey").toString();
            this.pbkdf2Salt = result.getMember("salt").toString();
            this.pbkdf2Iterations = Integer.valueOf(result.getMember("iterations").toString());
        } catch (IOException | ScriptException | NoSuchMethodException e) {
            throw new RuntimeException("BCKey file could not be parsed", e);
        }

        System.out.println("Parsing finished");
    }

    public void setPassword(final String pw) {
        if (pw.isEmpty()) {
            throw new InputMismatchException("Password can't be empty");
        }

        this.password = pw;
    }

    public String getPassword() {
        return this.password;
    }

    public String getEncryptedPrivateKey() {
        return this.encryptedPrivateKey;
    }

    public String getPBKDF2Salt() {
        return this.pbkdf2Salt;
    }

    public int getPBKDF2Iterations() {
        return this.pbkdf2Iterations;
    }
}
