package etf.openpgp.su182095dvv180421d;

import com.formdev.flatlaf.FlatDarculaLaf;
import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su182095dvv180421d.model.PublicKeyRing;
import etf.openpgp.su182095dvv180421d.views.KeyGenerate;
import etf.openpgp.su182095dvv180421d.views.KeysStoreLoad;
import etf.openpgp.su182095dvv180421d.views.PrivateKeyRingView;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.Security;

public class MainFrame extends JFrame {

    public MainFrame() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        PublicKeyRing.loadData();
        PrivateKeyRing.loadData();

        JTabbedPane jTabbedPane = new JTabbedPane();

        this.add(jTabbedPane);
        this.setTitle("Zastita podatak - Open PGP");
        Dimension size = Toolkit.getDefaultToolkit().getScreenSize();
        this.setBounds(
                size.width / 2 - Config.FRAME_WIDTH / 2,
                size.height / 2 - Config.FRAME_HEIGHT / 2,
                Config.FRAME_WIDTH,
                Config.FRAME_HEIGHT);
        this.setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        this.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                PrivateKeyRing.saveData();
                PublicKeyRing.saveData();
                dispose();
            }
        });

        jTabbedPane.addTab("Pregled prstena privatenih kljuceva", new PrivateKeyRingView(this));

        JPanel keysLoadStoreGenerate = new JPanel(new GridLayout(1, 2));
        keysLoadStoreGenerate.add(new KeysStoreLoad(
                publicKey -> PublicKeyRing.getInstance().addKey(publicKey),
                secretKey -> PrivateKeyRing.getInstance().addKey(secretKey),
                () -> PublicKeyRing.getInstance().getAllKeys().toArray(new PGPPublicKey[0]),
                () -> PrivateKeyRing.getInstance().getAllKeys().toArray(new PGPSecretKey[0])
        ));
        keysLoadStoreGenerate.add(new KeyGenerate());
        jTabbedPane.addTab("Manipulisanje kljucevima", keysLoadStoreGenerate);
    }

    public static void main(String[] args) {
        FlatDarculaLaf.setup();

        new MainFrame().setVisible(true);
    }
}
