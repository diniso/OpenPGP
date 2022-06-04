package etf.openpgp.su182095dvv180421d.model;

import etf.openpgp.su182095dvv180421d.Config;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public class PublicKeyRing extends KeyRing<PGPPublicKey> implements Serializable {
    List<PGPPublicKey> publicKeys = new ArrayList<>();

    public PGPPublicKey getKey(long keyId) {
        for (PGPPublicKey pk: publicKeys) {
            if (pk.getKeyID() == keyId) return pk;
        }
        return null;
    }

    public List<PGPPublicKey> getAllKeys() {
        return publicKeys;
    }

    public void addKey(PGPPublicKey key) {
        this.publicKeys.add(key);
    }

    public void removeKey(PGPPublicKey key) {
        this.publicKeys.remove(key);
    }

    public void removeKey(int index) {
        publicKeys.remove(index);
    }

    //
    private static PublicKeyRing singleton;

    public static PublicKeyRing getInstance() {
        if (singleton == null) {
            singleton = new PublicKeyRing();
        }
        return singleton;
    }

    public static void loadData() {
        if (singleton == null) {
            singleton = new PublicKeyRing();
        }

        File f = new File(Config.publicKeyRingFileSubfolder);
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
                singleton.addKey(LoadStoreKeys.readPublicKey(f.getAbsolutePath() + File.separator + filename));
            }
            catch (Exception e) {
                e.printStackTrace();
            }

        }
    }

    public static void saveData() {

        if (singleton == null) return;

        File f = new File(Config.publicKeyRingFileSubfolder);

        // create directory or delete existing data in it
        if (f.exists()) {
            if (!f.isDirectory()) {
                System.out.println("Subfolder for PublicKeyRing doesn't exists. It's file");
                return;
            }

            String[] filenames = f.list();
            if (filenames == null) {
                System.out.println("Couldn't get children for PublicKeyRing subfolder!");
                return;
            }

            for (String filename: filenames) {
                try {
                    LoadStoreKeys.readPublicKey(f.getAbsolutePath() + File.separator + filename);
                    new File(f.getAbsolutePath() + File.separator + filename).delete();
                } catch (Exception e) {
                    System.out.println("There is file other then .asc in PublicKeyRing subfolder and couldn't delete it");
                }

            }
        }
        else {
            if (!f.mkdir()) {
                System.out.println("Couldn't create folder for PublicKeyRing");
                return;
            }
        }

        for (PGPPublicKey sk: singleton.publicKeys) {
            String filename = "" + new Date().getTime() + ".asc";
            try {
                LoadStoreKeys.storePublicKey(sk, f.getAbsolutePath() + "/" + filename );
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}
