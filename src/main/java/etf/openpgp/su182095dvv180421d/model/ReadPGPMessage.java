package etf.openpgp.su182095dvv180421d.model;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SignatureException;
import java.util.Iterator;
import java.util.Optional;

public class ReadPGPMessage {

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

    public static Optional<String> decryptAndVerify(
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
                    return Optional.of("Pogresan password");
                }

                InputStream clear = ((PGPPublicKeyEncryptedData) pbe).getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
                plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());
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
                return Optional.of("T");
            }

            StringBuilder stringBuilder = new StringBuilder();

            for (int i = 0; i < onePassSignatureList.size(); i++) {
                PGPOnePassSignature ops = onePassSignatureList.get(0);
                publicKey = PublicKeyRing.getInstance().getSigningKey(ops.getKeyID());

                if (publicKey == null) {
                    return Optional.of("The key for sign verification is not found");
                }

                ops.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
                ops.update(output);
                PGPSignature signature = signatureList.get(i);

                if (!ops.verify(signature)) {
                    throw new SignatureException("Unsuccessful signature check");
                }

                Iterator<?> userIds = publicKey.getUserIDs();
                while (userIds.hasNext()) {
                    String userId = (String) userIds.next();
                    stringBuilder.append("Signed by: ").append(userId).append(System.lineSeparator());
                }
            }

            return Optional.of(stringBuilder.toString());
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return Optional.of("Error");



    }




}
