package etf.openpgp.su182095dvv180421d.model;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class AsymetricKeyGenerator {

    public enum BlockSize {
        BLOCK_1024,
        BLOCK_2048,
        BLOCK_4096;

        public int getBlockSize() {
            return switch (this) {
                case BLOCK_1024 -> 1024;
                case BLOCK_2048 -> 2048;
                case BLOCK_4096 -> 4096;
            };
        }
    }

    public static KeyPair generate(BlockSize blockSize) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(blockSize.getBlockSize());
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}
