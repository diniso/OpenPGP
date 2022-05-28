package etf.openpgp.su182095dvv180421d;

import etf.openpgp.su182095dvv180421d.model.AsymetricKeyGenerator;
import etf.openpgp.su182095dvv180421d.model.RsaUtil;
import etf.openpgp.su182095dvv180421d.views.PublicKeyRingView;

import javax.swing.*;
import java.awt.*;
import java.security.KeyPair;
import java.security.Security;

public class MainFrame extends JFrame {



    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        MainFrame mainFrame = new MainFrame();
        JTabbedPane jTabbedPane = new JTabbedPane();

        mainFrame.add(jTabbedPane);
        mainFrame.setTitle("Zastita podatak - Open PGP");
        Dimension size = Toolkit.getDefaultToolkit().getScreenSize();
        mainFrame.setBounds(
                size.width / 2 - Config.FRAME_WIDTH / 2,
                size.height / 2 - Config.FRAME_HEIGHT / 2,
                Config.FRAME_WIDTH,
                Config.FRAME_HEIGHT);
        mainFrame.setDefaultCloseOperation(EXIT_ON_CLOSE);

        jTabbedPane.addTab("Pregled prstena javnih kljuceva", new PublicKeyRingView());

        mainFrame.setVisible(true);

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
}
