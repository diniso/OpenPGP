package etf.openpgp.su182095dvv180421d.model;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;

import java.io.*;
import java.nio.file.Files;
import java.util.Iterator;
import java.util.List;

public class PGPMessageFactory {

    public void exportFile(File inputFile, File outputFile, PGPSecretKeyRing secretKey, List<PGPPublicKeyRing> publicKeyList, String password, boolean convertToRadix64, boolean compress, boolean isSigning) throws PGPException, IOException {
        if (!Files.exists(inputFile.toPath())) {
            throw new IllegalArgumentException("Ne postoji ulazni fajl");
        }

        BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_128);
        dataEncryptorBuilder.setWithIntegrityPacket(true); // It's added because kleopatra make a warning about not integrity
        PGPEncryptedDataGenerator pedg = new PGPEncryptedDataGenerator(dataEncryptorBuilder);

        pedg.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(Utils.getEncryptionPGPPublicKey(publicKeyList.get(0)))); // just for now

        OutputStream fileOutStream = new FileOutputStream(outputFile);
        OutputStream armoredFileOutputStream = fileOutStream;
        if (convertToRadix64) {
            armoredFileOutputStream = new ArmoredOutputStream(fileOutStream);
        }

        OutputStream outputStream = pedg.open(armoredFileOutputStream, new byte[1 << 16]);
        OutputStream compressedOutputStream = outputStream;
        if (compress) {
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
            compressedOutputStream = comData.open(outputStream);
        }

        PGPLiteralDataGenerator lg = new PGPLiteralDataGenerator();
        OutputStream literalDataOutStream;
        byte[] bytes = new FileInputStream(inputFile).readAllBytes();

        if (isSigning) {
            PGPPrivateKey privateKey = Utils.decryptSecretKey(Utils.getMasterPGPSecretKey(secretKey), password);
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
            Iterator<String> it = secretKey.getPublicKey().getUserIDs();

            if (it.hasNext()) {
                PGPSignatureSubpacketGenerator ssg = new PGPSignatureSubpacketGenerator();
                ssg.addSignerUserID(false, it.next());
                signatureGenerator.setHashedSubpackets(ssg.generate());
            }

            signatureGenerator.generateOnePassVersion(false).encode(compressedOutputStream);

            literalDataOutStream = lg.open(compressedOutputStream, PGPLiteralData.BINARY, inputFile);
            literalDataOutStream.write(bytes);

            signatureGenerator.update(bytes);
            signatureGenerator.generate().encode(compressedOutputStream);
        } else {
            literalDataOutStream = lg.open(compressedOutputStream, PGPLiteralData.BINARY, inputFile);
            literalDataOutStream.write(bytes);
        }

        literalDataOutStream.close();
        lg.close();
        if (compress) {
            compressedOutputStream.close();
        }
        outputStream.close();
        pedg.close();
        if (convertToRadix64) {
            armoredFileOutputStream.close();
        }
        fileOutStream.close();
    }
}
