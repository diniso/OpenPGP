package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.Config;
import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su182095dvv180421d.model.Utils;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;

public class DeletePrivateKeyDialog extends JDialog {

    private PGPSecretKey sk;
    private JLabel label = new JLabel("Enter password: ");
    private JTextField textField = new JTextField();
    private JButton button = new JButton("Delete");

    public DeletePrivateKeyDialog(JFrame parentFrame , PGPSecretKey sk) {
        super(parentFrame, "Delete private key", true);
        this.sk = sk;

        this.setLayout(new BorderLayout());

        JPanel panel = new JPanel(new GridLayout(1 , 2));
        label.setHorizontalAlignment(SwingConstants.RIGHT);
        panel.add(label);
        panel.add(textField);

        JPanel panel2 = new JPanel(new GridLayout(1 , 3));
        panel2.add(new JPanel());
        panel2.add(button);
        panel2.add(new JPanel());

        this.add(panel, BorderLayout.NORTH);
        this.add(panel2, BorderLayout.SOUTH);

        button.addActionListener(e -> {
            String password = textField.getText();
            try {
                PGPPrivateKey pk = Utils.decryptSecretKey(sk , password);
                // remove key

                PrivateKeyRing.getInstance().removeKey(sk);

                // close dialog
                DeletePrivateKeyDialog.this.setVisible(false);
                DeletePrivateKeyDialog.this.dispatchEvent(new WindowEvent(
                        DeletePrivateKeyDialog.this, WindowEvent.WINDOW_CLOSING));
            } catch (PGPException pgpException) {
                JOptionPane.showMessageDialog(null,
                        "Wrong password!",
                        "PopUp Dialog",
                        JOptionPane.INFORMATION_MESSAGE);
            }
        });
        Dimension size = Toolkit.getDefaultToolkit().getScreenSize();
        this.setBounds(size.width / 2 - Config.DIALOG_WIDTH / 2,
                size.height / 2 - Config.DIALOG_HEIGHT / 2,
                Config.DIALOG_WIDTH,
                Config.DIALOG_HEIGHT);
        this.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        this.setVisible(true);
    }
}
