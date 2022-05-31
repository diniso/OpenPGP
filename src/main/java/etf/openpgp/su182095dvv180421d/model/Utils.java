package etf.openpgp.su182095dvv180421d.model;

import etf.openpgp.su182095dvv180421d.Config;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.util.encoders.Base64;

import javax.swing.*;
import java.awt.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;
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

    public static PGPKeyRingGenerator generateKeyRingGenerator(String id, String password, int bitCount) throws PGPException {
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();


        RSAKeyGenerationParameters kgp = new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), bitCount, Config.CERTAINITY);
        kpg.init(kgp);

        Date now = new Date();

        PGPKeyPair rsakpSign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), now);
        PGPKeyPair rsakpEnc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), now);
        PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();
        signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        signhashgen.setPreferredSymmetricAlgorithms(false, new int[] { SymmetricKeyAlgorithmTags.CAST5, SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.TWOFISH, SymmetricKeyAlgorithmTags.AES_128 });
        signhashgen.setPreferredHashAlgorithms(false, new int[] { HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA1, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA224 });
        signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
        enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, Config.S2K_ITERATION_COUNT)).build(password.toCharArray());
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakpSign, id, sha1Calc, signhashgen.generate(), null, new BcPGPContentSignerBuilder(rsakpSign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), pske);
        keyRingGen.addSubKey(rsakpEnc, enchashgen.generate(), null);
        return keyRingGen;
    }

    public static JPanel wrapComponentToLayout(Component component, LayoutManager layoutManager) {
        JPanel wrapper = new JPanel(layoutManager);
        wrapper.add(component);
        return wrapper;
    }
}
