package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.model.ReadPGPMessage;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.Optional;

public class ReadMessageView extends JPanel {

    private final JButton button = new JButton("Load message file");
    private final JTextField passwordField = new JTextField();
    private final JButton buttonPassword = new JButton("Submite");
    private final JTextArea result = new JTextArea("");

    private String selectedFile;

    private static final String savedFile = "encrypted.asc";

    public ReadMessageView() {
        this.setLayout(new GridLayout(3, 1));

        JPanel panelTop = new JPanel(new GridLayout(2, 5));
        for (int i = 0; i < 2; i++) panelTop.add(new JPanel());
        panelTop.add(button);
        panelTop.setBorder(new EmptyBorder(10, 0, 0, 0));
        for (int i = 0; i < 7; i++) panelTop.add(new JPanel());
        this.add(panelTop);

        button.addActionListener(event -> {
            JFileChooser fileChooser = new JFileChooser();
            int openDialog = fileChooser.showOpenDialog(ReadMessageView.this);
            if (openDialog == JFileChooser.APPROVE_OPTION) {
                selectedFile = fileChooser.getSelectedFile().getAbsolutePath();

                try {
                    PGPSecretKey sk = ReadPGPMessage.getPGPSecretKeyFromFIle(selectedFile);
                    if (sk != null) {
                        disableTop();
                        enableMiddle();
                        return;
                    }
                    System.out.println("Pokrenuto ucitavanje bez passworda");
                    Optional<String> opsResult = ReadPGPMessage.decryptAndVerify(selectedFile, null, savedFile);
                    opsResult.ifPresent(result::setText);
                } catch (Exception ignored) {
                    result.setText("No key found for decryption");
                }
            }
        });

        JPanel panelMiddle = new JPanel(new GridLayout(2, 3));
        for (int i = 0; i < 1; i++) panelMiddle.add(new JPanel());

        JPanel panelMiddle2 = new JPanel(new GridLayout(1, 2));
        JLabel labela = new JLabel("Password: ");
        panelMiddle2.add(labela);
        panelMiddle2.add(passwordField);

        panelMiddle.add(panelMiddle2);

        for (int i = 0; i < 2; i++) panelMiddle.add(new JPanel());


        JPanel panelMiddle3 = new JPanel(new GridLayout(2, 3));
        for (int i = 0; i < 4; i++) panelMiddle3.add(new JPanel());
        panelMiddle3.add(buttonPassword);

        buttonPassword.addActionListener(event -> {
            System.out.println("Pokrenuto ucitavanje sa passwordom");
            Optional<String> opsResult = ReadPGPMessage.decryptAndVerify(selectedFile, passwordField.getText(), savedFile);
            opsResult.ifPresent(result::setText);

            disableMiddle();
            enableTop();
        });

        for (int i = 0; i < 1; i++) panelMiddle3.add(new JPanel());

        panelMiddle.add(panelMiddle3);

        for (int i = 0; i < 1; i++) panelMiddle.add(new JPanel());

        this.add(panelMiddle);

        disableMiddle();


        JPanel panelBotton = new JPanel(new GridLayout(2, 3));
        for (int i = 0; i < 4; i++) panelBotton.add(new JPanel());


        result.setEnabled(false);
        result.setBackground(new Color(240, 240, 240));
        panelBotton.add(result);
        panelBotton.setBorder(new EmptyBorder(0, 0, 20, 0));

        for (int i = 0; i < 1; i++) panelBotton.add(new JPanel());

        this.add(panelBotton);
    }

    private void disableMiddle() {
        buttonPassword.setEnabled(false);
        passwordField.setEditable(false);
    }

    private void enableMiddle() {
        buttonPassword.setEnabled(true);
        passwordField.setEditable(true);
    }

    private void disableTop() {
        button.setEnabled(false);
    }

    private void enableTop() {
        button.setEnabled(true);
    }

}
