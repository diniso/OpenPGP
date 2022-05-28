package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.Config;
import etf.openpgp.su182095dvv180421d.model.PrivateKey;
import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import org.bouncycastle.util.encoders.Base64;

import javax.swing.*;
import java.awt.*;
import java.util.Date;
import java.util.List;

public class PrivateKeyRingView extends JPanel {

    private JTable table;
    private JScrollPane sp;

    public PrivateKeyRingView() {
        this.setOpaque(false);
        sp = new JScrollPane();
        sp.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        setData();

        this.add(sp);
    }

    public void setData() {
        if (table != null) this.sp.remove(table);

        List<PrivateKey> pks = PrivateKeyRing.getInstance().getAllKeys();
        String data[][] = new String[pks.size()][5];
        String column[]={"Timestamp","Key ID","Public key", "Ecrypted private key", "User Id"};
        for (int i = 0 ; i < pks.size(); i++) {
            PrivateKey pk = pks.get(i);
            data[i][0] = new Date(pk.getTimeStamp()).toString();
            data[i][1] = Base64.toBase64String( pk.getKeyId());
            data[i][2] =  Base64.toBase64String( pk.getPublicKey());
            data[i][3] =  Base64.toBase64String( pk.getEncryptedPrivateKey());
            data[i][4] = pk.getUserId();
        }


        table = new JTable(data, column);
        table.setDefaultEditor(Object.class, null);

        this.sp.setViewportView(table);

        table.setFillsViewportHeight(true);

    }




}
