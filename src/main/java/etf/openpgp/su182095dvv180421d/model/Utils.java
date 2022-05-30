package etf.openpgp.su182095dvv180421d.model;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;

public class Utils {
    public static String getPGPPublicKeyIdBase64(PGPPublicKey publicKey) {
        return Base64.toBase64String(BigInteger.valueOf(publicKey.getKeyID()).toByteArray());
    }

    public static String getPGPPrivateKeyIdBase64(PGPSecretKey secretKey) {
        return Base64.toBase64String(BigInteger.valueOf(secretKey.getKeyID()).toByteArray());
    }

    public static PGPPrivateKey decryptSecretKey(PGPSecretKey secretKey, String password) throws PGPException {
        BcPBESecretKeyDecryptorBuilder decryptorBuilder = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
        PBESecretKeyDecryptor decryptorFactory = decryptorBuilder.build(password.toCharArray());
        return secretKey.extractPrivateKey(decryptorFactory);
    }
}
