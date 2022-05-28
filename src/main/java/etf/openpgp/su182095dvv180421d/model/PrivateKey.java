package etf.openpgp.su182095dvv180421d.model;

public class PrivateKey implements Key {
    int timeStamp;
    long keyId;
    byte[] publicKey;
    byte[] encryptedPrivateKey; // encrypted with the hash of the password
    String userId; // it's typically email, so it represented as the string

    public PrivateKey(int timeStamp, long keyId, byte[] publicKey, byte[] encryptedPrivateKey, String userId) {
        this.setTimeStamp(timeStamp);
        this.keyId = keyId;
        this.setPublicKey(publicKey);
        this.setEncryptedPrivateKey(encryptedPrivateKey);
        this.setUserId(userId);
    }

    public int getTimeStamp() {
        return timeStamp;
    }

    public void setTimeStamp(int timeStamp) {
        if (timeStamp < 0) {
            throw new IllegalArgumentException("Timestamp must be non negative number");
        }
        this.timeStamp = timeStamp;
    }

    public long getKeyId() {
        return keyId;
    }

    public void setKeyId(long keyId) {
        this.keyId = keyId;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Encrypted private key must be not null");
        }
        this.publicKey = publicKey;
    }

    public byte[] getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    public void setEncryptedPrivateKey(byte[] encryptedPrivateKey) {
        if (encryptedPrivateKey == null) {
            throw new IllegalArgumentException("Encrypted private key must be not null");
        }
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    @Override
    public byte[] getSerialized() {
        return new byte[0];
    }
}
