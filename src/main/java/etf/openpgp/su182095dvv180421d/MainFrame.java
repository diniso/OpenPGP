package etf.openpgp.su182095dvv180421d;

import com.formdev.flatlaf.FlatLightLaf;
import etf.openpgp.su182095dvv180421d.model.AsymetricKeyGenerator;
import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su182095dvv180421d.model.PublicKeyRing;
import etf.openpgp.su182095dvv180421d.model.RsaUtil;
import etf.openpgp.su182095dvv180421d.views.KeysStoreLoad;
//import etf.openpgp.su182095dvv180421d.views.PublicKeyRingView;
import org.bouncycastle.openpgp.*;
import etf.openpgp.su182095dvv180421d.views.PrivateKeyRingAddView;
import etf.openpgp.su182095dvv180421d.views.PrivateKeyRingView;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.security.KeyPair;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

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
//        jTabbedPane.addTab("Pregled prstena javnih kljuceva", new PublicKeyRingView());
        jTabbedPane.addTab("Uvoz i izvoz kljuceva", new KeysStoreLoad(
                publicKey -> PublicKeyRing.getInstance().addKey(publicKey),
                secretKey -> PrivateKeyRing.getInstance().addKey(secretKey),
                () -> PublicKeyRing.getInstance().getAllKeys().toArray(new PGPPublicKey[0]),
                () -> PrivateKeyRing.getInstance().getAllKeys().toArray(new PGPSecretKey[0])
        ));

        KeyPair keyPair = AsymetricKeyGenerator.generate(AsymetricKeyGenerator.BlockSize.BLOCK_1024);

        String cipher = RsaUtil.encrypt(
                keyPair.getPublic().getEncoded(),
                "hello");

        String original = RsaUtil.decrypt(
                keyPair.getPrivate().getEncoded(),
                cipher);

        System.out.println(cipher);
        System.out.println(original);
    }

    public static void main(String[] args) {
        FlatLightLaf.setup();

        new MainFrame().setVisible(true);
    }
}
