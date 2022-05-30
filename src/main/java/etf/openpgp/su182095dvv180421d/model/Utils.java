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
import java.util.Locale;

public class Utils {
    public static String getPGPPublicKeyIdBase64(PGPPublicKey publicKey) {
        return new BigInteger(Long.toUnsignedString(publicKey.getKeyID()), 10).toString(16).toUpperCase(Locale.ROOT);
    }

    public static String getPGPPrivateKeyIdBase64(PGPSecretKey secretKey) {
        return new BigInteger(Long.toUnsignedString(secretKey.getKeyID()), 10).toString(16).toUpperCase(Locale.ROOT);
    }

    public static PGPPrivateKey decryptSecretKey(PGPSecretKey secretKey, String password) throws PGPException {
        BcPBESecretKeyDecryptorBuilder decryptorBuilder = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider());
        PBESecretKeyDecryptor decryptorFactory = decryptorBuilder.build(password.toCharArray());
        return secretKey.extractPrivateKey(decryptorFactory);
    }
}
