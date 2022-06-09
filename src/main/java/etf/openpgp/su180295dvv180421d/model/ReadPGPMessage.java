package etf.openpgp.su180295dvv180421d.model;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.util.Iterator;

public class ReadPGPMessage {

    public static String decryptAndVerify(
            String decryptedFileName,
            String password,
            String filename) {

        try {
            OutputStream fOut = new FileOutputStream(filename);

            PGPObjectFactory pgpF = new PGPObjectFactory(
                    PGPUtil.getDecoderStream(new FileInputStream(decryptedFileName)),
                    new BcKeyFingerprintCalculator());

            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();
            PGPObjectFactory plainFact = pgpF;

            StringBuilder stringBuilder = new StringBuilder();

            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;

                Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
                PGPPrivateKey sKey = null;
                PGPEncryptedData pbe = null;

                while (sKey == null && it.hasNext()) {
                    pbe = it.next();

                    try {
                        sKey = Utils.decryptSecretKey(PrivateKeyRing.getInstance().getEncryptionKey(((PGPPublicKeyEncryptedData) pbe).getKeyID()), password);
                    } catch (Exception ignored) {

                    }
                }

                if (sKey == null) {
                    return "Wrong password";
                }

                InputStream clear = ((PGPPublicKeyEncryptedData) pbe).getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
                plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

                stringBuilder.append("Successfully decrypted message!");
            }

            PGPOnePassSignatureList onePassSignatureList = null;
            PGPSignatureList signatureList = null;
            PGPCompressedData compressedData;

            Object msgDecryption = plainFact.nextObject();
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();

            while (msgDecryption != null) {

                if (msgDecryption instanceof PGPCompressedData) {
                    compressedData = (PGPCompressedData) msgDecryption;
                    plainFact = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator());
                    msgDecryption = plainFact.nextObject();
                }

                if (msgDecryption instanceof PGPLiteralData) {

                    Streams.pipeAll(((PGPLiteralData) msgDecryption).getInputStream(), outStream);
                }
                if (msgDecryption instanceof PGPSignatureList) {
                    signatureList = (PGPSignatureList) msgDecryption;
                }
                if (msgDecryption instanceof PGPOnePassSignatureList) {
                    onePassSignatureList = (PGPOnePassSignatureList) msgDecryption;
                }

                msgDecryption = plainFact.nextObject();
            }

            outStream.close();
            fOut.write(outStream.toByteArray());
            fOut.close();

            PGPPublicKey publicKey;
            byte[] output = outStream.toByteArray();

            if (onePassSignatureList == null || signatureList == null) {
                return "Unknown error!";
            }



            for (int i = 0; i < onePassSignatureList.size(); i++) {
                PGPOnePassSignature ops = onePassSignatureList.get(0);
                publicKey = PublicKeyRing.getInstance().getSigningKey(ops.getKeyID());

                if (publicKey == null) {
                    return "The key for sign verification is not found";
                }

                ops.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
                ops.update(output);
                PGPSignature signature = signatureList.get(i);

                if (!ops.verify(signature)) {
                    return "Unsuccessful signature check";
                }

                stringBuilder.append("Successfully signed!");

                Iterator<?> userIds = publicKey.getUserIDs();
                while (userIds.hasNext()) {
                    String userId = (String) userIds.next();
                    stringBuilder.append("Signed by: ").append(userId).append(System.lineSeparator());
                }
            }

            return stringBuilder.toString();
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return "Unknown error!!";



    }




}
