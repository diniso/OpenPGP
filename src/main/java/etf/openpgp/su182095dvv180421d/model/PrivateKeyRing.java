package etf.openpgp.su182095dvv180421d.model;

import etf.openpgp.su182095dvv180421d.Config;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.*;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class PrivateKeyRing extends KeyRing<PGPSecretKey> implements Serializable {

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


    //
    private static PrivateKeyRing singleton;

    public static PrivateKeyRing getInstance() {
        if (singleton == null) {
            singleton = new PrivateKeyRing();
        }

        return singleton;
    }

    public static void loadData() {
        if (singleton == null) {
            singleton = new PrivateKeyRing();
        }

        File f = new File(Config.privateKeyRingSubfolder);
        if (!f.exists() || !f.isDirectory()) {
            System.out.println("Subdirectory for PrivateKeyRing doesn't exists or is not folder! 1");
            return;
        }

        String[] filenames = f.list();
        if (filenames == null) {
            System.out.println("Subdirectory for PrivateKeyRing doesn't exists or is not folder! 2");
            return;
        }

        for (String filename: filenames) {
            try {
                singleton.addKey(LoadStoreKeys.readSecretKey(f.getAbsolutePath() + File.separator + filename));
            }
            catch (Exception e) {
                e.printStackTrace();
            }

        }
    }

    public static void saveData(){

        if (singleton == null) return;

        File f = new File(Config.privateKeyRingSubfolder);

        // create directory or delete existing data in it
        if (f.exists()) {
            if (!f.isDirectory()) {
                System.out.println("Subfolder for PrivateKeyRing doesn't exists. It's file");
                return;
            }

            String[] filenames = f.list();
            if (filenames == null) {
                System.out.println("Couldn't get children for PrivateRingSubfolder!");
                return;
            }

            for (String filename: filenames) {
                try {
                    LoadStoreKeys.readSecretKey(f.getAbsolutePath() + File.separator + filename);
                    new File(f.getAbsolutePath() + File.separator + filename).delete();
                } catch (Exception e) {
                    System.out.println("There is file other then .asc in PrivateKeyRing subfolder and couldn't delete it");
                }

            }
        }
        else {
            if (!f.mkdir()) {
                System.out.println("Couldn't create folder for PrivateKeyRing");
                return;
            }
        }

        for (PGPSecretKey sk: singleton.privateKeys) {
            String filename = "" + new Date().getTime() + ".asc";
            try {
                LoadStoreKeys.storeSecretKey(sk, f.getAbsolutePath() + File.separator + filename );
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}
