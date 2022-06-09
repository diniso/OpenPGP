package etf.openpgp.su180295dvv180421d.model;

import etf.openpgp.su180295dvv180421d.Config;
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

import javax.swing.*;
import java.awt.*;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
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
        signhashgen.setPreferredSymmetricAlgorithms(false, new int[] { SymmetricKeyAlgorithmTags.TRIPLE_DES, SymmetricKeyAlgorithmTags.AES_128 });
        signhashgen.setPreferredHashAlgorithms(false, new int[] { HashAlgorithmTags.SHA1 });
        signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);
        PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
        enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc, Config.S2K_ITERATION_COUNT)).build(password.toCharArray());
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakpSign, id, sha1Calc, signhashgen.generate(), null, new BcPGPContentSignerBuilder(rsakpSign.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), pske);
        keyRingGen.addSubKey(rsakpEnc, enchashgen.generate(), null);
        return keyRingGen;
    }

    public static JPanel wrapComponentToLayout(Component component, LayoutManager layoutManager) {
        JPanel wrapper = new JPanel(layoutManager);
        wrapper.add(component);
        return wrapper;
    }

    public static boolean isPasswordCorrectForSecretKey(PGPSecretKey pgpSecretKey, String password) {
        try {
            decryptSecretKey(pgpSecretKey, password);
            return true;
        } catch (PGPException e) {
            return false;
        }
    }

    public static PGPSecretKey getMasterPGPSecretKey(PGPSecretKeyRing pgpSecretKeyRing) {
        Iterator<PGPSecretKey> secretKeys = pgpSecretKeyRing.getSecretKeys();
        while (secretKeys.hasNext()) {
            PGPSecretKey secretKey = secretKeys.next();
            if (secretKey.isMasterKey()) {
                return secretKey;
            }
        }
        throw new IllegalArgumentException("PGP Secret key ring ne poseduje master kljuc");
    }

    public static PGPPublicKey getMasterPGPPublicKey(PGPPublicKeyRing pgpPublicKeyRing) {
        Iterator<PGPPublicKey> publicKeys = pgpPublicKeyRing.getPublicKeys();
        while (publicKeys.hasNext()) {
            PGPPublicKey publicKey = publicKeys.next();
            if (publicKey.isMasterKey()) {
                return publicKey;
            }
        }
        throw new IllegalArgumentException("PGP Public key ring ne poseduje master kljuc");
    }

    public static PGPPublicKeyRing getPublicKeysFromSecretKeyRing(PGPSecretKeyRing pgpSecretKey) {
        ArrayList<PGPPublicKey> list = new ArrayList<>();

        Iterator<PGPPublicKey> publicKeys = pgpSecretKey.getPublicKeys();
        while (publicKeys.hasNext()) {
            PGPPublicKey pub = publicKeys.next();
            list.add(pub);
        }
        publicKeys = pgpSecretKey.getExtraPublicKeys();
        while (publicKeys.hasNext()) {
            PGPPublicKey pub = publicKeys.next();
            list.add(pub);
        }

        return new PGPPublicKeyRing(list);
    }

    public static PGPPublicKey getEncryptionPGPPublicKey(PGPPublicKeyRing pgpPublicKeys) {
        Iterator<PGPPublicKey> publicKeys = pgpPublicKeys.getPublicKeys();
        while (publicKeys.hasNext()) {
            PGPPublicKey publicKey = publicKeys.next();
            if (publicKey.isEncryptionKey()) {
                return publicKey;
            }
        }
        throw new IllegalArgumentException("PGP Public key ring ne poseduje kljuc za enkripciju");
    }

    public static PGPSecretKey getEncryptionPGPSecretKey(PGPSecretKeyRing pgpSecretKeys) {
        Iterator<PGPSecretKey> secretKeys = pgpSecretKeys.getSecretKeys();
        while (secretKeys.hasNext()) {
            PGPSecretKey secretKey = secretKeys.next();
            if (!secretKey.isSigningKey()) {
                return secretKey;
            }
        }
        throw new IllegalArgumentException("PGP Secret key ring ne poseduje kljuc za dekripciju");
    }

    public static PGPSecretKey getPGPSecretKeyFromFIle(String filename) throws Exception {
        try {
            PGPObjectFactory pgpF = new PGPObjectFactory(
                    PGPUtil.getDecoderStream(new FileInputStream(filename)),
                    new BcKeyFingerprintCalculator());


            Object o = pgpF.nextObject();

            if (!(o instanceof PGPEncryptedDataList)) return null;

            PGPEncryptedDataList enc = (PGPEncryptedDataList) o;

            Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
            if (!it.hasNext()) {
                return null;
            }
            while (it.hasNext()) {
                PGPEncryptedData pbe = it.next();

                PGPSecretKey sk = PrivateKeyRing.getInstance().getEncryptionKey(((PGPPublicKeyEncryptedData) pbe).getKeyID());

                if (sk != null) return sk;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        throw new Exception("No key found");
    }
}
