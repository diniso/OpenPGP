package etf.openpgp.su180295dvv180421d.model;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;

public class LoadStoreKeys {

    // Will be moved to dedicated file soon
    public static void storePublicKey(PGPPublicKeyRing pgpPublicKey, String absolutePath) throws IOException {
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(absolutePath));
        armoredOutputStream.write(pgpPublicKey.getEncoded());
        armoredOutputStream.close();
    }

    public static void storeSecretKey(PGPSecretKeyRing pgpSecretKey, String absolutePath) throws IOException {
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(absolutePath));
        armoredOutputStream.write(pgpSecretKey.getEncoded());
        armoredOutputStream.close();
    }

    public static ArrayList<PGPPublicKeyRing> readPublicKeys(String path) throws IOException, PGPException {
        InputStream fileInputStream = new FileInputStream(path);
        fileInputStream = PGPUtil.getDecoderStream(fileInputStream);

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(fileInputStream, new JcaKeyFingerprintCalculator());

        Iterator<PGPPublicKeyRing> keyRingIterator = pgpPub.getKeyRings();
        ArrayList<PGPPublicKeyRing> publicKeys = new ArrayList<>();
        while (keyRingIterator.hasNext()) {
            publicKeys.add(keyRingIterator.next());
        }

        fileInputStream.close();
        return publicKeys;
    }

    public static ArrayList<PGPSecretKeyRing> readSecretKeys(String path) throws IOException, PGPException {
        InputStream fileInputStream = new FileInputStream(path);
        fileInputStream = PGPUtil.getDecoderStream(fileInputStream);

        PGPSecretKeyRingCollection pgpPub = new PGPSecretKeyRingCollection(fileInputStream, new JcaKeyFingerprintCalculator());

        Iterator<PGPSecretKeyRing> keyRingIterator = pgpPub.getKeyRings();
        ArrayList<PGPSecretKeyRing> secretKeys = new ArrayList<>();
        while (keyRingIterator.hasNext()) {
            secretKeys.add(keyRingIterator.next());
        }

        fileInputStream.close();
        return secretKeys;
    }
}
