package etf.openpgp.su182095dvv180421d.model;

import etf.openpgp.su182095dvv180421d.Config;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class PublicKeyRing extends KeyRing<PGPPublicKey> {
    List<PGPPublicKey> privateKeys = new ArrayList<>();

    public PGPPublicKey getKey(long keyId) {
        for (PGPPublicKey pk: privateKeys) {
            if (pk.getKeyID() == keyId) return pk;
        }
        return null;
    }

    public List<PGPPublicKey> getAllKeys() {
        return privateKeys;
    }

    public void addKey(PGPPublicKey key) {
        this.privateKeys.add(key);
    }

    public void removeKey(PGPPublicKey key) {
        this.privateKeys.remove(key);
    }

    public void removeKey(int index) {
        privateKeys.remove(index);
    }

    //
    private static PublicKeyRing singleton;

    public static PublicKeyRing getInstance() {
        if (singleton == null) {
            singleton = new PublicKeyRing();
        }

        return singleton;
    }
}
