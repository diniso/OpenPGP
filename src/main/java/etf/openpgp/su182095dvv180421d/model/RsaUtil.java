package etf.openpgp.su182095dvv180421d.model;

import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class RsaUtil {
    public static String encrypt(byte[] key, String str) {
        try {
            RSAEngine rsaEngine = new RSAEngine();
            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.createKey(key);
            rsaEngine.init(true, asymmetricKeyParameter);
            byte[] bytes = rsaEngine.processBlock(str.getBytes(StandardCharsets.US_ASCII), 0, str.getBytes(StandardCharsets.US_ASCII).length);
            return Base64.toBase64String(bytes);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(byte[] key, String cipher) {
        try {
            RSAEngine rsaEngine = new RSAEngine();
            AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(key);
            rsaEngine.init(true, asymmetricKeyParameter);
            byte[] cipherBytes = Base64.decode(cipher);
            byte[] decryptedBytes = rsaEngine.processBlock(cipherBytes, 0, cipherBytes.length);
            return new String(decryptedBytes);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
