package etf.openpgp.su182095dvv180421d;

import com.formdev.flatlaf.FlatLightLaf;
import etf.openpgp.su182095dvv180421d.model.AsymetricKeyGenerator;
import etf.openpgp.su182095dvv180421d.model.RsaUtil;
import etf.openpgp.su182095dvv180421d.views.KeysStoreLoad;
import etf.openpgp.su182095dvv180421d.views.PublicKeyRingView;
import org.bouncycastle.openpgp.*;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.security.KeyPair;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

public class MainFrame extends JFrame {

    PGPPublicKeyRing pgpPublicKeys;
    PGPSecretKeyRing pgpSecretKeys;

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

        pgpPublicKeys = new PGPPublicKeyRing(new LinkedList<>());
        pgpSecretKeys = new PGPSecretKeyRing(new LinkedList<>());


        jTabbedPane.addTab("Pregled prstena javnih kljuceva", new PublicKeyRingView());
        jTabbedPane.addTab("Uvoz i izvoz kljuceva", new KeysStoreLoad(
                publicKey -> pgpPublicKeys = PGPPublicKeyRing.insertPublicKey(pgpPublicKeys, publicKey),
                secretKey -> pgpSecretKeys = PGPSecretKeyRing.insertSecretKey(pgpSecretKeys, secretKey),
                () -> {
                    List<PGPPublicKey> list = new LinkedList<>();
                    pgpPublicKeys.getPublicKeys().forEachRemaining(list::add);
                    return list.toArray(PGPPublicKey[]::new);
                },
                () -> {
                    List<PGPSecretKey> list = new LinkedList<>();
                    pgpSecretKeys.getSecretKeys().forEachRemaining(list::add);
                    return list.toArray(PGPSecretKey[]::new);
                }
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
