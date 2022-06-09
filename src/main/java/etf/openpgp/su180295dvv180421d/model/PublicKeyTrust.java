package etf.openpgp.su180295dvv180421d.model;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;

import java.util.Iterator;

public class PublicKeyTrust {

    public static boolean getOwnerTrust(PGPPublicKey pk) {
        return false;
    }

    public static boolean getSignatureTrust(PGPPublicKey pk) {
        return false;
    }

    public static String getSignatureToString(Iterator<PGPSignature> signatures) {
        String toStr = "";
        while(signatures.hasNext()) {
            PGPSignature signature = signatures.next();
            if ("".equals(toStr)) toStr += signature.getKeyID();
            else toStr += "," + signature.getKeyID();
        }
        return toStr;
    }
}
