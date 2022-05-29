package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.model.Callback;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.io.*;
import java.util.Arrays;
import java.util.Iterator;
import java.util.function.Supplier;

public class KeysStoreLoad extends JPanel {

    static class PGPPrivateKeyComboBox {
        PGPSecretKey pgpSecretKey;

        public PGPPrivateKeyComboBox(PGPSecretKey pgpSecretKey) {
            this.pgpSecretKey = pgpSecretKey;
        }

        @Override
        public String toString() {
            Iterator<String> userIDs = pgpSecretKey.getUserIDs();
            if (userIDs.hasNext()) {
                return "ID: %s, Korisnik: %s".formatted(pgpSecretKey.getKeyID(), userIDs.next());
            }
            return "ID: %s".formatted(pgpSecretKey.getKeyID());
        }
    }

    static class PGPPublicKeyComboBox {
        PGPPublicKey pgpPublicKey;

        public PGPPublicKeyComboBox(PGPPublicKey pgpPublicKey) {
            this.pgpPublicKey = pgpPublicKey;
        }

        @Override
        public String toString() {
            Iterator<String> userIDs = pgpPublicKey.getUserIDs();
            if (userIDs.hasNext()) {
                return "ID: %s, Korisnik: %s".formatted(pgpPublicKey.getKeyID(), userIDs.next());
            }
            return "ID: %s".formatted(pgpPublicKey.getKeyID());
        }
    }

    public KeysStoreLoad(Callback<PGPPublicKey> publicKeyAction, Callback<PGPSecretKey> secretKeyAction, Supplier<PGPPublicKey[]> publicKeysSupplier, Supplier<PGPSecretKey[]> secretKeysSupplier) {
        super(new BorderLayout());

        JPanel centerPanel = new JPanel(new GridLayout(2, 1));

        JPanel privateOrPublicKeyChoosePanel = new JPanel();
        privateOrPublicKeyChoosePanel.setBorder(new TitledBorder("Vrsta kljuca"));
        JRadioButton publicKeyRB = new JRadioButton("Javni kljuc", true);
        JRadioButton privateKeyRB = new JRadioButton("Privatni kljuc");
        ButtonGroup publicPrivateKeyRGB = new ButtonGroup();
        publicPrivateKeyRGB.add(publicKeyRB);
        publicPrivateKeyRGB.add(privateKeyRB);
        privateOrPublicKeyChoosePanel.add(publicKeyRB);
        privateOrPublicKeyChoosePanel.add(privateKeyRB);
        centerPanel.add(privateOrPublicKeyChoosePanel);

        JPanel loadOrStoreChoosePanel = new JPanel(new GridLayout(3, 1));
        loadOrStoreChoosePanel.setBorder(new TitledBorder("Operacija"));
        JRadioButton loadKeyRB = new JRadioButton("Ucitaj kljuc", true);
        JRadioButton storeKeyRB = new JRadioButton("Sacuvaj kljuc");
        JComboBox<PGPPrivateKeyComboBox> privateKeyJComboBox = new JComboBox<>(Arrays.stream(secretKeysSupplier.get()).map(PGPPrivateKeyComboBox::new).toArray(PGPPrivateKeyComboBox[]::new));
        privateKeyJComboBox.setEnabled(false);
        JComboBox<PGPPublicKeyComboBox> publicKeyJComboBox = new JComboBox<>(Arrays.stream(publicKeysSupplier.get()).map(PGPPublicKeyComboBox::new).toArray(PGPPublicKeyComboBox[]::new));
        publicKeyJComboBox.setEnabled(false);
        ButtonGroup loadStoreKeyRGB = new ButtonGroup();
        loadStoreKeyRGB.add(loadKeyRB);
        loadStoreKeyRGB.add(storeKeyRB);
        loadOrStoreChoosePanel.add(loadKeyRB);
        loadOrStoreChoosePanel.add(storeKeyRB);
        loadOrStoreChoosePanel.add(privateKeyJComboBox);
        centerPanel.add(loadOrStoreChoosePanel);
        storeKeyRB.addItemListener(selected -> {
            privateKeyJComboBox.setEnabled(selected.getStateChange() == ItemEvent.SELECTED);
            publicKeyJComboBox.setEnabled(selected.getStateChange() == ItemEvent.SELECTED);
        });

        JPanel operationsPanel = new JPanel();
        JButton button = new JButton("Izvrsi");
        operationsPanel.add(button);
        this.add(centerPanel, BorderLayout.CENTER);
        this.add(operationsPanel, BorderLayout.SOUTH);

        button.addActionListener(event -> {
            if (loadKeyRB.isSelected()) {
                if (publicKeyRB.isSelected()) {
                    JFileChooser fileChooser = new JFileChooser();
                    int openDialog = fileChooser.showOpenDialog(KeysStoreLoad.this);
                    if (openDialog == JFileChooser.APPROVE_OPTION) {
                        File selectedFile = fileChooser.getSelectedFile();
                        try {
                            PGPPublicKey publicKey = readPublicKey(selectedFile.getAbsolutePath());
                            publicKeyAction.callback(publicKey);
                            publicKeyJComboBox.addItem(new PGPPublicKeyComboBox(publicKey));
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(KeysStoreLoad.this, e.getLocalizedMessage(), "Greska", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
                else if (privateKeyRB.isSelected()) {
                    JFileChooser fileChooser = new JFileChooser();
                    int openDialog = fileChooser.showOpenDialog(KeysStoreLoad.this);
                    if (openDialog == JFileChooser.APPROVE_OPTION) {
                        File selectedFile = fileChooser.getSelectedFile();
                        try {
                            PGPSecretKey secretKey = readSecretKey(selectedFile.getAbsolutePath());
                            secretKeyAction.callback(secretKey);
                            privateKeyJComboBox.addItem(new PGPPrivateKeyComboBox(secretKey));
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(KeysStoreLoad.this, e.getLocalizedMessage(), "Greska", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
            }
            else if (storeKeyRB.isSelected()) {
                if (publicKeyRB.isSelected()) {
                    JFileChooser fileChooser = new JFileChooser();
                    int openDialog = fileChooser.showSaveDialog(KeysStoreLoad.this);
                    if (openDialog == JFileChooser.APPROVE_OPTION) {
                        File selectedFile = fileChooser.getSelectedFile();
                        try {
                            PGPPublicKeyComboBox publicKeyComboBox = (PGPPublicKeyComboBox) publicKeyJComboBox.getSelectedItem();
                            storePublicKey(publicKeyComboBox.pgpPublicKey, selectedFile.getAbsolutePath());
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(KeysStoreLoad.this, e.getLocalizedMessage(), "Greska", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
                else if (privateKeyRB.isSelected()) {
                    JFileChooser fileChooser = new JFileChooser();
                    int openDialog = fileChooser.showSaveDialog(KeysStoreLoad.this);
                    if (openDialog == JFileChooser.APPROVE_OPTION) {
                        File selectedFile = fileChooser.getSelectedFile();
                        try {
                            PGPPrivateKeyComboBox privateKeyComboBox = (PGPPrivateKeyComboBox) privateKeyJComboBox.getSelectedItem();
                            storeSecretKey(privateKeyComboBox.pgpSecretKey, selectedFile.getAbsolutePath());
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(KeysStoreLoad.this, e.getLocalizedMessage(), "Greska", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
            }
        });
    }

    // Will be moved to dedicated file soon
    private void storePublicKey(PGPPublicKey pgpPublicKey, String absolutePath) throws IOException {
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(absolutePath));
        armoredOutputStream.addHeader("Comment", "Generated by su180295");
        armoredOutputStream.write(pgpPublicKey.getEncoded());
        armoredOutputStream.close();
    }

    private void storeSecretKey(PGPSecretKey pgpSecretKey, String absolutePath) throws IOException {
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(absolutePath));
        armoredOutputStream.addHeader("Comment", "Generated by su180295");
        armoredOutputStream.write(pgpSecretKey.getEncoded());
        armoredOutputStream.close();
    }

    PGPPublicKey readPublicKey(String path) throws IOException, PGPException {
        InputStream fileInputStream = new FileInputStream(path);
        fileInputStream = PGPUtil.getDecoderStream(fileInputStream);

        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(fileInputStream, new JcaKeyFingerprintCalculator());

        Iterator<PGPPublicKeyRing> keyRingIterator = pgpPub.getKeyRings();
        while (keyRingIterator.hasNext()) {
            Iterator<PGPPublicKey> publicKeys = keyRingIterator.next().getPublicKeys();
            while (publicKeys.hasNext()) {
                PGPPublicKey publicKey = publicKeys.next();
                System.out.println("Encryption key = " + publicKey.isEncryptionKey() + ";Key id = " + publicKey.getKeyID() + ";User id = " + publicKey.getUserIDs().hasNext());
                if (publicKey.isEncryptionKey()) {
                    fileInputStream.close();
                    return publicKey;
                }
            }
        }

        fileInputStream.close();
        return null;
    }

    PGPSecretKey readSecretKey(String path) throws IOException, PGPException {
        InputStream fileInputStream = new FileInputStream(path);
        fileInputStream = PGPUtil.getDecoderStream(fileInputStream);

        PGPSecretKeyRingCollection pgpPub = new PGPSecretKeyRingCollection(fileInputStream, new JcaKeyFingerprintCalculator());

        Iterator<PGPSecretKeyRing> keyRingIterator = pgpPub.getKeyRings();
        while (keyRingIterator.hasNext()) {
            Iterator<PGPSecretKey> secretKeys = keyRingIterator.next().getSecretKeys();
            while (secretKeys.hasNext()) {
                PGPSecretKey secretKey = secretKeys.next();
                System.out.println("Master = " + secretKey.isMasterKey() + ";Key id = " + secretKey.getKeyID() + ";User id = " + secretKey.getUserIDs().hasNext());
                if (secretKey.isMasterKey()) {
                    fileInputStream.close();
                    return secretKey;
                }
            }
        }

        fileInputStream.close();
        return null;
    }
}
