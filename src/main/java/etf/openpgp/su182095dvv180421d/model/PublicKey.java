package etf.openpgp.su182095dvv180421d.model;

public class PublicKey implements Key {
    int timeStamp;
    long keyId;
    byte[] publicKey;
    int ownerTrust;
    String userId; // it's typically email, so it represented as the string
    int keyLegitimacy;

    public PublicKey(int timeStamp, long keyId, byte[] publicKey, int ownerTrust, String userId, int keyLegitimacy) {
        this.setTimeStamp(timeStamp);
        this.keyId = keyId;
        this.setPublicKey(publicKey);
        this.setOwnerTrust(ownerTrust);
        this.setUserId(userId);
        this.keyLegitimacy = keyLegitimacy;
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

    public int getOwnerTrust() {
        return ownerTrust;
    }

    public void setOwnerTrust(int ownerTrust) {
        this.ownerTrust = ownerTrust;
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
