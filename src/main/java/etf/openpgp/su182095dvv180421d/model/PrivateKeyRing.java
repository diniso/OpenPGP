package etf.openpgp.su182095dvv180421d.model;

import etf.openpgp.su182095dvv180421d.Config;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class PrivateKeyRing implements KeyRing {

    List<PrivateKey> privateKeys = new ArrayList<>();

    public PrivateKey getKey(byte[] keyId) {
        for (PrivateKey pk: privateKeys) {
            if (pk.getKeyId().equals(keyId)) return pk;
        }
        return null;
    }

    public List<PrivateKey> getAllKeys() {
        return privateKeys;
    }

    public void addKey(PrivateKey key) {
        this.privateKeys.add(key);
    }

    public void removeKey(PrivateKey key) {
        this.privateKeys.remove(key);
    }

    public void removeKey(int index) {
        privateKeys.remove(index);
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
            singleton.privateKeys.add(new PrivateKey(kp.getPublic().getEncoded(), kp.getPrivate().getEncoded(), "Vlade"));
        }
        return singleton;
    }

    public static void saveData() {
        if (singleton == null) return;
        singleton.saveData(Config.privateKeyRingFile);
    }
}
