package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.model.Observer;
import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su182095dvv180421d.model.Utils;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.encoders.Base64;

import javax.swing.*;
import java.text.SimpleDateFormat;
import java.util.Iterator;
import java.util.List;

public class PrivateKeyRingView extends JPanel implements Observer<List<PGPSecretKey>> {

    private JTable table;
    private final JScrollPane sp;

    public PrivateKeyRingView() {
        this.setOpaque(false);
        sp = new JScrollPane();
        sp.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        PrivateKeyRing.getInstance().addObserver(this);
        setData(PrivateKeyRing.getInstance().getAllKeys());

        this.add(sp);
    }

    public void setData(List<PGPSecretKey> pks) {
        if (table != null) this.sp.remove(table);

        String[][] data = new String[pks.size()][4];
        String[] column = {"Timestamp", "Key ID", "Public key", "User Id"};
        for (int i = 0; i < pks.size(); i++) {
            PGPSecretKey pk = pks.get(i);

            data[i][0] = new SimpleDateFormat("yyyy-MM-dd hh:mm").format(pk.getPublicKey().getCreationTime());
            data[i][1] = Utils.getPGPPrivateKeyIdBase64(pk);
            data[i][2] = Base64.toBase64String(pk.getPublicKey().getPublicKeyPacket().getKey().getEncoded());
            data[i][3] = "";
            Iterator<String> userIDs = pk.getUserIDs();
            if (userIDs.hasNext()) {
                data[i][3] = userIDs.next();
            }
        }


        table = new JTable(data, column);
        table.setDefaultEditor(Object.class, null);

        this.sp.setViewportView(table);

        table.setFillsViewportHeight(true);
    }

    @Override
    public void observableChanged(List<PGPSecretKey> pks) {
        setData(pks);
    }
}
