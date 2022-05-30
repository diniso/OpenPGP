package etf.openpgp.su182095dvv180421d.model;

import etf.openpgp.su182095dvv180421d.Config;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class PrivateKeyRing extends KeyRing<PGPSecretKey> {

    List<PGPSecretKey> privateKeys = new ArrayList<>();

    public PGPSecretKey getKey(long keyId) {
        for (PGPSecretKey pk: privateKeys) {
            if (pk.getKeyID() == keyId) return pk;
        }
        return null;
    }

    public List<PGPSecretKey> getAllKeys() {
        return privateKeys;
    }

    public void addKey(PGPSecretKey key) {
        this.privateKeys.add(key);
        notifyObservers(privateKeys);
    }

    public void removeKey(PGPSecretKey key) {
        this.privateKeys.remove(key);
        notifyObservers(privateKeys);
    }

    public void removeKey(int index) {
        privateKeys.remove(index);
        notifyObservers(privateKeys);
    }

    private void loadData(String filename) {

    }

    private void saveData(String filename) {

    }


    //
    private static PrivateKeyRing singleton;

    public static PrivateKeyRing getInstance() {
        if (singleton == null) {
            singleton = new PrivateKeyRing();
            singleton.loadData(Config.privateKeyRingFile);
        }

        for (int i = 0 ; i < 50 ; i++) {
            KeyPair kp = AsymetricKeyGenerator.generate(AsymetricKeyGenerator.BlockSize.BLOCK_1024);
//            new PGPSecretKey()
//            singleton.privateKeys.add(new PrivateKey(kp.getPublic().getEncoded(), kp.getPrivate().getEncoded(), "Vlade"));
        }
        return singleton;
    }

    public static void saveData() {
        if (singleton == null) return;
        singleton.saveData(Config.privateKeyRingFile);
    }
}
