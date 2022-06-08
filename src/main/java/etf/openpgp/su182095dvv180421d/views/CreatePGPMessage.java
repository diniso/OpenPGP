package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.model.PGPMessageFactory;
import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su182095dvv180421d.model.PublicKeyRing;
import etf.openpgp.su182095dvv180421d.model.Utils;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.examples.SignedFileProcessor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.List;

public class CreatePGPMessage extends JPanel {

    File destinationFile;
    File inputFile;

    public static class SymmetricKeyAlgorithmTagsComboBox {

        int algorithm;

        public SymmetricKeyAlgorithmTagsComboBox(int algorithm) {
            if (algorithm < SymmetricKeyAlgorithmTags.NULL || algorithm > SymmetricKeyAlgorithmTags.CAMELLIA_256) {
                throw new IllegalArgumentException("Algorithm is not recognized");
            }
            this.algorithm = algorithm;
        }

        @Override
        public String toString() {
            return switch (algorithm) {
                case SymmetricKeyAlgorithmTags.AES_128 -> "AES 128";
                case SymmetricKeyAlgorithmTags.TRIPLE_DES -> "Trostruki DES";
                default -> Integer.toString(algorithm);
            };
        }
    }

    public static final SymmetricKeyAlgorithmTagsComboBox[] SUPPORTED_ALGORITHMS = new SymmetricKeyAlgorithmTagsComboBox[] {
            new SymmetricKeyAlgorithmTagsComboBox(SymmetricKeyAlgorithmTags.AES_128),
            new SymmetricKeyAlgorithmTagsComboBox(SymmetricKeyAlgorithmTags.TRIPLE_DES)
    };

    public CreatePGPMessage() {
        super(new GridLayout(5, 1, 20, 10));

        JPanel encryptionPanelKeys = new JPanel(new GridLayout(2,1, 10, 10));
        encryptionPanelKeys.add(new JLabel("Odaberite javne kljuceve:", SwingConstants.CENTER));
        JList<KeysStoreLoad.PGPPublicKeyComboBox> publicKeyComboBoxJList = new JList<>();
        populateJListWithPublicKeys(publicKeyComboBoxJList, PublicKeyRing.getInstance().getAllKeys());
        encryptionPanelKeys.add(publicKeyComboBoxJList);

        JPanel encryptionPanelAlgorithm = new JPanel(new GridLayout(2, 1, 10, 10));
        JLabel algorithmJLabel = new JLabel("Algoritam", SwingConstants.CENTER);
        JComboBox<SymmetricKeyAlgorithmTagsComboBox> keyAlgorithmTagsJComboBox = new JComboBox<>(SUPPORTED_ALGORITHMS);
        encryptionPanelAlgorithm.add(algorithmJLabel);
        encryptionPanelAlgorithm.add(keyAlgorithmTagsJComboBox);

        JCheckBox encryptionCheckbox = new JCheckBox("Primeni enkripciju", true);

        JPanel encryptionPanel = new JPanel(new GridLayout(1,3, 10, 5));
        encryptionPanel.add(Utils.wrapComponentToLayout(encryptionCheckbox, new FlowLayout()));
        encryptionPanel.add(encryptionPanelKeys);
        encryptionPanel.add(encryptionPanelAlgorithm);
        encryptionPanel.setBorder(new TitledBorder("Enkripcija"));

        this.add(encryptionPanel);

        JPanel signaturePanel = new JPanel(new GridLayout(1,2));
        signaturePanel.setBorder(new TitledBorder("Potpisivanje"));

        JCheckBox makeSignatureCheckBox = new JCheckBox("Izvrsi potpis", true);

        JPanel signatureKeyPanel = new JPanel(new GridLayout(2,1, 10, 10));
        signatureKeyPanel.add(new JLabel("Odaberite tajni kljucev:", SwingConstants.CENTER));
        JComboBox<KeysStoreLoad.PGPPrivateKeyComboBox> secretKeyComboBoxJComboBox = new JComboBox<>();
        populateComboboxWithSecretKeys(secretKeyComboBoxJComboBox, PrivateKeyRing.getInstance().getAllKeys());
        signatureKeyPanel.add(secretKeyComboBoxJComboBox);

        signaturePanel.add(Utils.wrapComponentToLayout(makeSignatureCheckBox, new FlowLayout()));
        signaturePanel.add(signatureKeyPanel);


        this.add(signaturePanel);

        JPanel filesPanel = new JPanel(new GridLayout(1, 2));

        JPanel chooseInputFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton chooseInputFileButton = new JButton("Odaberite ulazni fajl");
        JLabel inputFileLabel = new JLabel("Fajl: ");
        chooseInputFilePanel.setBorder(new TitledBorder("Odabir ulaznog fajla"));
        chooseInputFilePanel.add(chooseInputFileButton);
        chooseInputFilePanel.add(inputFileLabel);
        chooseInputFileButton.addActionListener(event -> {
            JFileChooser fileChooser = new JFileChooser();
            int openDialog = fileChooser.showOpenDialog(CreatePGPMessage.this);
            if (openDialog == JFileChooser.APPROVE_OPTION) {
                inputFile = fileChooser.getSelectedFile();
                inputFileLabel.setText("Fajl: " + inputFile.getAbsolutePath());
            }
        });
        filesPanel.add(chooseInputFilePanel);

        JPanel chooseDestinationFilePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton chooseFileButton = new JButton("Odaberite fajl");
        JLabel fileLabel = new JLabel("Odrediste: ");
        chooseDestinationFilePanel.setBorder(new TitledBorder("Odabir mesta za cuvanje"));
        chooseDestinationFilePanel.add(chooseFileButton);
        chooseDestinationFilePanel.add(fileLabel);
        chooseFileButton.addActionListener(event -> {
            JFileChooser fileChooser = new JFileChooser();
            int openDialog = fileChooser.showSaveDialog(CreatePGPMessage.this);
            if (openDialog == JFileChooser.APPROVE_OPTION) {
                destinationFile = fileChooser.getSelectedFile();
                fileLabel.setText("Odrediste: " + destinationFile.getAbsolutePath());
            }
        });
        filesPanel.add(chooseDestinationFilePanel);

        this.add(filesPanel);

        JPanel additionOptionsPanel = new JPanel(new GridLayout(1, 2));
        additionOptionsPanel.setBorder(new TitledBorder("Dodatne opcije"));
        JCheckBox radix64CheckBox = new JCheckBox("Konverzija u radix 64", true);
        JCheckBox compressionCheckBox = new JCheckBox("Kompresija", true);
        additionOptionsPanel.add(Utils.wrapComponentToLayout(radix64CheckBox, new FlowLayout()));
        additionOptionsPanel.add(Utils.wrapComponentToLayout(compressionCheckBox, new FlowLayout()));
        this.add(additionOptionsPanel);

        JButton performAction = new JButton("Sacuvaj fajl");
        this.add(Utils.wrapComponentToLayout(performAction, new FlowLayout()));
        performAction.addActionListener(event -> {
            KeysStoreLoad.PGPPrivateKeyComboBox privateKeyComboBoxJComboBoxSelectedItem = ((KeysStoreLoad.PGPPrivateKeyComboBox) secretKeyComboBoxJComboBox.getSelectedItem());
            if (privateKeyComboBoxJComboBoxSelectedItem == null) {
                JOptionPane.showMessageDialog(CreatePGPMessage.this, "Morate odabrati privatni kljuc", "Greska", JOptionPane.ERROR_MESSAGE);
                return;
            }

            List<PGPPublicKeyRing> publicKeys = publicKeyComboBoxJList.getSelectedValuesList().stream().map(container -> container.pgpPublicKey).toList();
            if (publicKeys.isEmpty()) {
                JOptionPane.showMessageDialog(CreatePGPMessage.this, "Morate odabrati javni kljuc za enkripciju", "Greska", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (inputFile == null) {
                JOptionPane.showMessageDialog(CreatePGPMessage.this, "Morate odabrati ulazni fajl za obradu", "Greska", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (!Files.isReadable(inputFile.toPath())) {
                JOptionPane.showMessageDialog(CreatePGPMessage.this, "Fajl ne postoji ili su nedovoljne permisije za njegovo citanje", "Greska", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (destinationFile == null) {
                JOptionPane.showMessageDialog(CreatePGPMessage.this, "Morate odabrati izlazni fajl", "Greska", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String password = JOptionPane.showInputDialog(CreatePGPMessage.this, "Unesite lozinku pod kojom cuvate privatni kljuc", "Unos lozinke", JOptionPane.QUESTION_MESSAGE);
            if (password == null) {
                return;
            }
            if (!Utils.isPasswordCorrectForSecretKey(Utils.getMasterPGPSecretKey(privateKeyComboBoxJComboBoxSelectedItem.pgpSecretKey), password)) {
                JOptionPane.showMessageDialog(CreatePGPMessage.this, "Unete lozinka nije tacna", "Greska", JOptionPane.ERROR_MESSAGE);
                return;
            }

            try {
                PGPMessageFactory pgpMessageFactory = new PGPMessageFactory();
                int algorithm = SymmetricKeyAlgorithmTags.NULL;
                if (encryptionCheckbox.isSelected()) {
                    algorithm = ((SymmetricKeyAlgorithmTagsComboBox) keyAlgorithmTagsJComboBox.getSelectedItem()).algorithm;
                }
                pgpMessageFactory.exportFile(inputFile, destinationFile, privateKeyComboBoxJComboBoxSelectedItem.pgpSecretKey, publicKeys, password, radix64CheckBox.isSelected(), compressionCheckBox.isSelected(), makeSignatureCheckBox.isSelected(), algorithm);
                JOptionPane.showMessageDialog(CreatePGPMessage.this, "Fajl je uspesno obradjen", "Uspeh", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(CreatePGPMessage.this, e.getLocalizedMessage(), "Greska", JOptionPane.ERROR_MESSAGE);
            }

        });

        PrivateKeyRing.getInstance().addObserver(privateKeys -> populateComboboxWithSecretKeys(secretKeyComboBoxJComboBox, privateKeys));

        PublicKeyRing.getInstance().addObserver(publicKeys -> populateJListWithPublicKeys(publicKeyComboBoxJList, publicKeys));
    }

    private void populateJListWithPublicKeys(JList<KeysStoreLoad.PGPPublicKeyComboBox> publicKeyJList, List<PGPPublicKeyRing> publicKeys) {
        KeysStoreLoad.PGPPublicKeyComboBox[] publicKeyComboBoxes = publicKeys.stream()
                .map(KeysStoreLoad.PGPPublicKeyComboBox::new)
                .toArray(KeysStoreLoad.PGPPublicKeyComboBox[]::new);
        publicKeyJList.setModel(new DefaultComboBoxModel<>(publicKeyComboBoxes));
    }

    private static void populateComboboxWithSecretKeys(JComboBox<KeysStoreLoad.PGPPrivateKeyComboBox> privateKeyComboBoxJComboBox, List<PGPSecretKeyRing> secretKeys) {
        KeysStoreLoad.PGPPrivateKeyComboBox[] privateKeyComboBoxes = secretKeys.stream()
                .map(KeysStoreLoad.PGPPrivateKeyComboBox::new)
                .toArray(KeysStoreLoad.PGPPrivateKeyComboBox[]::new);
        privateKeyComboBoxJComboBox.setModel(new DefaultComboBoxModel<>(privateKeyComboBoxes));
    }
}
