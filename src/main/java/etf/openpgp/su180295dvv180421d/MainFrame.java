package etf.openpgp.su180295dvv180421d;

import com.formdev.flatlaf.FlatDarculaLaf;
import etf.openpgp.su180295dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su180295dvv180421d.model.PublicKeyRing;
import etf.openpgp.su180295dvv180421d.views.*;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

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
        jTabbedPane.addTab("Pregled prstena javnih kljuceva", new PublicKeyRingView());

        JPanel keysLoadStoreGenerate = new JPanel(new GridLayout(1, 2));
        keysLoadStoreGenerate.add(new KeysStoreLoad(
                publicKey -> PublicKeyRing.getInstance().addKey(publicKey),
                secretKey -> PrivateKeyRing.getInstance().addKey(secretKey),
                () -> PublicKeyRing.getInstance().getAllKeys().toArray(new PGPPublicKeyRing[0]),
                () -> PrivateKeyRing.getInstance().getAllKeys().toArray(new PGPSecretKeyRing[0])
        ));
        keysLoadStoreGenerate.add(new KeyGenerate());
        jTabbedPane.addTab("Manipulisanje kljucevima", keysLoadStoreGenerate);
        jTabbedPane.addTab("Generisanje poruke", new CreatePGPMessage());
        jTabbedPane.addTab("Citanje poruke", new ReadMessageView());
    }

    public static void main(String[] args) {
        FlatDarculaLaf.setup();

        new MainFrame().setVisible(true);
    }
}
