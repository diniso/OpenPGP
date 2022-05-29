package etf.openpgp.su182095dvv180421d.model;

import java.util.Date;

public class PrivateKey implements Key {
    private long timeStamp;
    private byte[] keyId;
    private byte[] publicKey;
    private byte[] encryptedPrivateKey; // encrypted with the hash of the password
    private String userId; // it's typically email, so it represented as the string

    public PrivateKey(byte[] publicKey, byte[] encryptedPrivateKey, String userId) {
        this.setPublicKey(publicKey);
        this.setEncryptedPrivateKey(encryptedPrivateKey);
        this.setKeyId(publicKey);
        this.userId = userId;
        this.timeStamp = new Date().getTime();
    }

    // getters

    public long getTimeStamp() {
        return timeStamp;
    }

    public String getUserId() {
        return userId;
    }

    public byte[] getKeyId() {return keyId;}

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    // setters

    private void setPublicKey(byte[] publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key must be not null");
        }
        this.publicKey = publicKey;
    }

    private void setEncryptedPrivateKey(byte[] encryptedPrivateKey) {
        if (encryptedPrivateKey == null) {
            throw new IllegalArgumentException("Encrypted private key must be not null");
        }
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    private void setKeyId(byte[] publicKey) {
        this.keyId = new byte[8];
        for (int i = 0 ; i < 8 ; i++)
            keyId[i] = publicKey[publicKey.length-8+i];
    }

    // For export

    @Override
    public byte[] getSerialized() {
        return new byte[0];
    }
}
