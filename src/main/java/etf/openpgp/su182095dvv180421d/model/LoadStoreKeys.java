package etf.openpgp.su182095dvv180421d.model;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

public class LoadStoreKeys {

    // Will be moved to dedicated file soon
    public static void storePublicKey(PGPPublicKey pgpPublicKey, String absolutePath) throws IOException {
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(absolutePath));
        armoredOutputStream.write(pgpPublicKey.getEncoded());
        armoredOutputStream.close();
    }

    public static void storeSecretKey(PGPSecretKey pgpSecretKey, String absolutePath) throws IOException {
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(absolutePath));
        armoredOutputStream.write(pgpSecretKey.getEncoded());
        armoredOutputStream.close();
    }

    public static PGPPublicKey readPublicKey(String path) throws IOException, PGPException {
        InputStream fileInputStream = new FileInputStream(path);
        fileInputStream = PGPUtil.getDecoderStream(fileInputStream);

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(fileInputStream, new JcaKeyFingerprintCalculator());

        Iterator<PGPPublicKeyRing> keyRingIterator = pgpPub.getKeyRings();
        while (keyRingIterator.hasNext()) {
            Iterator<PGPPublicKey> publicKeys = keyRingIterator.next().getPublicKeys();
            while (publicKeys.hasNext()) {
                PGPPublicKey publicKey = publicKeys.next();
                System.out.println("Encryption key = " + publicKey.isEncryptionKey() + ";Key id = " + publicKey.getKeyID() + ";User id = " + publicKey.getUserIDs().hasNext());
                if (!publicKey.isEncryptionKey()) {
                    fileInputStream.close();
                    return publicKey;
                }
            }
        }

        fileInputStream.close();
        return null;
    }

    public static PGPSecretKey readSecretKey(String path) throws IOException, PGPException {
        InputStream fileInputStream = new FileInputStream(path);
        fileInputStream = PGPUtil.getDecoderStream(fileInputStream);

        PGPSecretKeyRingCollection pgpPub = new PGPSecretKeyRingCollection(fileInputStream, new JcaKeyFingerprintCalculator());

        Iterator<PGPSecretKeyRing> keyRingIterator = pgpPub.getKeyRings();
        while (keyRingIterator.hasNext()) {
            Iterator<PGPSecretKey> secretKeys = keyRingIterator.next().getSecretKeys();
            while (secretKeys.hasNext()) {
                PGPSecretKey secretKey = secretKeys.next();
                System.out.println("Master = " + secretKey.isMasterKey() + ";Key id = " + secretKey.getKeyID() + ";User id = " + secretKey.getUserIDs().hasNext());
                if (secretKey.isMasterKey()) {
                    fileInputStream.close();
                    return secretKey;
                }
            }
        }

        fileInputStream.close();
        return null;
    }
}
