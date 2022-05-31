package etf.openpgp.su182095dvv180421d;

import com.formdev.flatlaf.FlatDarculaLaf;
import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su182095dvv180421d.model.PublicKeyRing;
import etf.openpgp.su182095dvv180421d.views.KeyGenerate;
import etf.openpgp.su182095dvv180421d.views.KeysStoreLoad;
import etf.openpgp.su182095dvv180421d.views.PrivateKeyRingAddView;
import etf.openpgp.su182095dvv180421d.views.PrivateKeyRingView;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import javax.swing.*;
import java.awt.*;
import java.security.Security;

public class MainFrame extends JFrame {

    public MainFrame() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        JTabbedPane jTabbedPane = new JTabbedPane();

        this.add(jTabbedPane);
        this.setTitle("Zastita podatak - Open PGP");
        Dimension size = Toolkit.getDefaultToolkit().getScreenSize();
        this.setBounds(
                size.width / 2 - Config.FRAME_WIDTH / 2,
                size.height / 2 - Config.FRAME_HEIGHT / 2,
                Config.FRAME_WIDTH,
                Config.FRAME_HEIGHT);
        this.setDefaultCloseOperation(EXIT_ON_CLOSE);

        jTabbedPane.addTab("Pregled prstena privatenih kljuceva", new PrivateKeyRingView());
        jTabbedPane.addTab("Dodovanje u prsten privatnih kljuceva", new PrivateKeyRingAddView());

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
