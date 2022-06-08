package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.model.PGPMessageFactory;
import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su182095dvv180421d.model.PublicKeyRing;
import etf.openpgp.su182095dvv180421d.model.Utils;
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

    public CreatePGPMessage() {
        super(new GridLayout(5, 1, 20, 10));

        JPanel encryptionPanel = new JPanel(new GridLayout(2,1, 10, 10));
        encryptionPanel.setBorder(new TitledBorder("Enkripcija"));
        encryptionPanel.add(new JLabel("Odaberite javne kljuceve:", SwingConstants.CENTER));
        JList<KeysStoreLoad.PGPPublicKeyComboBox> publicKeyComboBoxJList = new JList<>();
        populateJListWithPublicKeys(publicKeyComboBoxJList, PublicKeyRing.getInstance().getAllKeys());
        encryptionPanel.add(publicKeyComboBoxJList);
        this.add(encryptionPanel);

        JPanel signaturePanel = new JPanel(new GridLayout(2,1, 10, 10));
        signaturePanel.setBorder(new TitledBorder("Potpisivanje"));
        signaturePanel.add(new JLabel("Odaberite tajni kljucev:", SwingConstants.CENTER));
        JComboBox<KeysStoreLoad.PGPPrivateKeyComboBox> secretKeyComboBoxJComboBox = new JComboBox<>();
        populateComboboxWithSecretKeys(secretKeyComboBoxJComboBox, PrivateKeyRing.getInstance().getAllKeys());
        signaturePanel.add(secretKeyComboBoxJComboBox);
        this.add(signaturePanel);

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
        this.add(chooseInputFilePanel);

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
        this.add(chooseDestinationFilePanel);

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
                pgpMessageFactory.exportFile(inputFile, destinationFile, privateKeyComboBoxJComboBoxSelectedItem.pgpSecretKey, publicKeys, password, true, true, true);
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
