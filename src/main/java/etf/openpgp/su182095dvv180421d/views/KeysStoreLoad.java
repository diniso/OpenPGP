package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.model.*;
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
import java.util.List;
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
                return "ID: %s, Korisnik: %s".formatted(Utils.getPGPPrivateKeyIdBase64(pgpSecretKey), userIDs.next());
            }
            return "ID: %s".formatted(Utils.getPGPPrivateKeyIdBase64(pgpSecretKey));
        }
    }

//    static class PGPPublicKeyComboBox {
//        PGPPublicKey pgpPublicKey;
//
//        public PGPPublicKeyComboBox(PGPPublicKey pgpPublicKey) {
//            this.pgpPublicKey = pgpPublicKey;
//        }
//
//        @Override
//        public String toString() {
//            Iterator<String> userIDs = pgpPublicKey.getUserIDs();
//            if (userIDs.hasNext()) {
//                return "ID: %s, Korisnik: %s".formatted(Utils.getPGPPublicKeyIdBase64(pgpPublicKey), userIDs.next());
//            }
//            return "ID: %s".formatted(Utils.getPGPPublicKeyIdBase64(pgpPublicKey));
//        }
//    }

    public KeysStoreLoad(Callback<PGPPublicKey> publicKeyAction, Callback<PGPSecretKey> secretKeyAction, Supplier<PGPPublicKey[]> publicKeysSupplier, Supplier<PGPSecretKey[]> secretKeysSupplier) {
        super(new BorderLayout());

        JPanel centerPanel = new JPanel(new GridLayout(2, 1));

        JPanel privateOrPublicKeyChoosePanel = new JPanel(new GridLayout(2, 1));
        privateOrPublicKeyChoosePanel.setBorder(new TitledBorder("Vrsta kljuca"));
        JRadioButton publicKeyRB = new JRadioButton("Javni kljuc", true);
        JRadioButton privateKeyRB = new JRadioButton("Privatni kljuc");
        ButtonGroup publicPrivateKeyRGB = new ButtonGroup();
        publicPrivateKeyRGB.add(publicKeyRB);
        publicPrivateKeyRGB.add(privateKeyRB);
        privateOrPublicKeyChoosePanel.add(Utils.wrapComponentToLayout(publicKeyRB, new FlowLayout(FlowLayout.CENTER)));
        privateOrPublicKeyChoosePanel.add(Utils.wrapComponentToLayout(privateKeyRB, new FlowLayout(FlowLayout.CENTER)));

        centerPanel.add(privateOrPublicKeyChoosePanel);

        JPanel loadOrStoreChoosePanel = new JPanel(new GridLayout(3, 1));
        loadOrStoreChoosePanel.setBorder(new TitledBorder("Operacija"));
        JRadioButton loadKeyRB = new JRadioButton("Ucitaj kljuc", true);
        JRadioButton storeKeyRB = new JRadioButton("Sacuvaj kljuc");
        JComboBox<PGPPrivateKeyComboBox> privateKeyJComboBox = new JComboBox<>(Arrays.stream(secretKeysSupplier.get()).map(PGPPrivateKeyComboBox::new).toArray(PGPPrivateKeyComboBox[]::new));
        privateKeyJComboBox.setEnabled(false);
//        JComboBox<PGPPublicKeyComboBox> publicKeyJComboBox = new JComboBox<>(Arrays.stream(publicKeysSupplier.get()).map(PGPPublicKeyComboBox::new).toArray(PGPPublicKeyComboBox[]::new));
//        publicKeyJComboBox.setEnabled(false);
        ButtonGroup loadStoreKeyRGB = new ButtonGroup();
        loadStoreKeyRGB.add(loadKeyRB);
        loadStoreKeyRGB.add(storeKeyRB);
        loadOrStoreChoosePanel.add(Utils.wrapComponentToLayout(loadKeyRB, new FlowLayout(FlowLayout.CENTER)));
        loadOrStoreChoosePanel.add(Utils.wrapComponentToLayout(storeKeyRB, new FlowLayout(FlowLayout.CENTER)));
        loadOrStoreChoosePanel.add(Utils.wrapComponentToLayout(privateKeyJComboBox, new FlowLayout(FlowLayout.CENTER)));
        centerPanel.add(loadOrStoreChoosePanel);
        storeKeyRB.addItemListener(selected -> {
            privateKeyJComboBox.setEnabled(selected.getStateChange() == ItemEvent.SELECTED);
//            publicKeyJComboBox.setEnabled(selected.getStateChange() == ItemEvent.SELECTED);
        });

        JPanel operationsPanel = new JPanel();
        JButton button = new JButton("Izvrsi");
        operationsPanel.add(button);
        this.add(centerPanel, BorderLayout.CENTER);
        this.add(operationsPanel, BorderLayout.SOUTH);

        TitledBorder border = new TitledBorder("Uvoz i izvoz kljuceva");
        border.setTitleJustification(TitledBorder.CENTER);
        this.setBorder(border);

        button.addActionListener(event -> {
            if (loadKeyRB.isSelected()) {
                if (publicKeyRB.isSelected()) {
                    JFileChooser fileChooser = new JFileChooser();
                    int openDialog = fileChooser.showOpenDialog(KeysStoreLoad.this);
                    if (openDialog == JFileChooser.APPROVE_OPTION) {
                        File selectedFile = fileChooser.getSelectedFile();
                        try {
                            PGPPublicKey publicKey = LoadStoreKeys.readPublicKey(selectedFile.getAbsolutePath());
                            publicKeyAction.callback(publicKey);
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
                            PGPSecretKey secretKey = LoadStoreKeys.readSecretKey(selectedFile.getAbsolutePath());
                            secretKeyAction.callback(secretKey);
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(KeysStoreLoad.this, e.getLocalizedMessage(), "Greska", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
            }
            else if (storeKeyRB.isSelected()) {
                if (publicKeyRB.isSelected()) {
                    if (privateKeyJComboBox.getItemCount() == 0) {
                        JOptionPane.showMessageDialog(KeysStoreLoad.this, "Ne postoji kljuc za izvoz", "", JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                    JFileChooser fileChooser = new JFileChooser();
                    int openDialog = fileChooser.showSaveDialog(KeysStoreLoad.this);
                    if (openDialog == JFileChooser.APPROVE_OPTION) {
                        File selectedFile = fileChooser.getSelectedFile();
                        try {
                            PGPPrivateKeyComboBox privateKeyComboBox = (PGPPrivateKeyComboBox) privateKeyJComboBox.getSelectedItem();
                            LoadStoreKeys.storePublicKey(privateKeyComboBox.pgpSecretKey.getPublicKey(), selectedFile.getAbsolutePath());
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(KeysStoreLoad.this, e.getLocalizedMessage(), "Greska", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
                else if (privateKeyRB.isSelected()) {
                    if (privateKeyJComboBox.getItemCount() == 0) {
                        JOptionPane.showMessageDialog(KeysStoreLoad.this, "Ne postoji kljuc za izvoz", "", JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                    JFileChooser fileChooser = new JFileChooser();
                    int openDialog = fileChooser.showSaveDialog(KeysStoreLoad.this);
                    if (openDialog == JFileChooser.APPROVE_OPTION) {
                        File selectedFile = fileChooser.getSelectedFile();
                        try {
                            PGPPrivateKeyComboBox privateKeyComboBox = (PGPPrivateKeyComboBox) privateKeyJComboBox.getSelectedItem();
                            LoadStoreKeys.storeSecretKey(privateKeyComboBox.pgpSecretKey, selectedFile.getAbsolutePath());
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(KeysStoreLoad.this, e.getLocalizedMessage(), "Greska", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
            }
        });

        PrivateKeyRing.getInstance().addObserver(secretKeys -> {
            PGPPrivateKeyComboBox[] comboBoxes = secretKeys.stream().map(PGPPrivateKeyComboBox::new).toArray(PGPPrivateKeyComboBox[]::new);
            privateKeyJComboBox.setModel(new DefaultComboBoxModel<>(comboBoxes));
        });

//        PublicKeyRing.getInstance().addObserver(publicKeys -> {
//            PGPPublicKeyComboBox[] comboBoxes = publicKeys.stream().map(PGPPublicKeyComboBox::new).toArray(PGPPublicKeyComboBox[]::new);
//            publicKeyJComboBox.setModel(new DefaultComboBoxModel<>(comboBoxes));
//        });

//        publicKeyRB.addItemListener(event -> {
//            if (event.getStateChange() == ItemEvent.SELECTED) {
//                loadOrStoreChoosePanel.remove(2);
//                loadOrStoreChoosePanel.add(Utils.wrapComponentToLayout(publicKeyJComboBox, new FlowLayout(FlowLayout.CENTER)));
//                loadOrStoreChoosePanel.revalidate();
//            }
//        });
//        privateKeyRB.addItemListener(event -> {
//            if (event.getStateChange() == ItemEvent.SELECTED) {
//                loadOrStoreChoosePanel.remove(2);
//                loadOrStoreChoosePanel.add(Utils.wrapComponentToLayout(privateKeyJComboBox, new FlowLayout(FlowLayout.CENTER)));
//                loadOrStoreChoosePanel.revalidate();
//            }
//        });
    }
}
