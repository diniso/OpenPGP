package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su182095dvv180421d.model.Utils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

public class KeyGenerate extends JPanel {

    public static final String[] algorithmsForEncryption = new String[]{"RSA 1024", "RSA 2048", "RSA 4096"};

    public KeyGenerate() {
        super(new GridLayout(0, 1, 10, 20));
        TitledBorder border = new TitledBorder("Generisanje kljuceva");
        border.setTitleJustification(TitledBorder.CENTER);
        this.setBorder(border);

        JLabel nameLabel = new JLabel("Ime korisnika");
        JTextField nameTextField = new JTextField(20);
        JPanel namePanel = new JPanel(new GridLayout(2, 1));
        namePanel.add(nameLabel);
        namePanel.add(nameTextField);
        this.add(namePanel);

        JLabel emailLabel = new JLabel("Email");
        JTextField emailTextField = new JTextField(20);
        JPanel emailPanel = new JPanel(new GridLayout(2, 1));
        emailPanel.add(emailLabel);
        emailPanel.add(emailTextField);
        this.add(emailPanel);

        JLabel algorithmLabel = new JLabel("Algoritam");
        JComboBox<String> algorithmComboBox = new JComboBox<>(algorithmsForEncryption);
        JPanel algorithmPanel = new JPanel(new GridLayout(2, 1));
        algorithmPanel.add(algorithmLabel);
        algorithmPanel.add(algorithmComboBox);
        this.add(algorithmPanel);

        JLabel passwordLabel = new JLabel("Lozinka");
        JTextField passwordTextField = new JPasswordField(20);
        JPanel passwordPanel = new JPanel(new GridLayout(2, 1));
        passwordPanel.add(passwordLabel);
        passwordPanel.add(passwordTextField);
        this.add(passwordPanel);

        JButton generateButton = new JButton("Izgenerisi kljuceve");
        JPanel generateButtonPanel = new JPanel();
        generateButtonPanel.add(generateButton);
        this.add(generateButtonPanel);

        generateButton.addActionListener(event -> {
            String name = nameTextField.getText().trim();
            String email = emailTextField.getText().trim();
            String password = passwordTextField.getText();
            if (algorithmComboBox.getSelectedIndex() == -1) {
                JOptionPane.showMessageDialog(KeyGenerate.this, "Morate odabrati algoritam", "Popunite sva polja", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            String algorithm = algorithmsForEncryption[algorithmComboBox.getSelectedIndex()];

            if (name.isEmpty()) {
                JOptionPane.showMessageDialog(KeyGenerate.this, "Morate uneti ime", "Popunite sva polja", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (email.isEmpty()) {
                JOptionPane.showMessageDialog(KeyGenerate.this, "Morate uneti email", "Popunite sva polja", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (password.isEmpty()) {
                JOptionPane.showMessageDialog(KeyGenerate.this, "Morate uneti lozinku", "Popunite sva polja", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (algorithm.isEmpty()) {
                JOptionPane.showMessageDialog(KeyGenerate.this, "Morate uneti algoritam", "Popunite sva polja", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            int rsaEncryptionBlockLength = Integer.parseInt(algorithm.split(" ")[1]);
            try {
                PGPKeyRingGenerator pgpKeyRingGenerator = Utils.generateKeyRingGenerator(name + " <" + email + ">", password, rsaEncryptionBlockLength);
                PGPSecretKeyRing secretKey = pgpKeyRingGenerator.generateSecretKeyRing();

                PrivateKeyRing.getInstance().addKey(secretKey);
            } catch (PGPException e) {
                e.printStackTrace();
            }

        });
    }
}
