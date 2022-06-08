package etf.openpgp.su182095dvv180421d.views;

import etf.openpgp.su182095dvv180421d.model.Observer;
import etf.openpgp.su182095dvv180421d.model.PrivateKeyRing;
import etf.openpgp.su182095dvv180421d.model.PublicKeyRing;
import etf.openpgp.su182095dvv180421d.model.Utils;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.util.encoders.Base64;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.Iterator;
import java.util.List;

public class PublicKeyRingView extends JPanel implements Observer<List<PGPPublicKeyRing>> {

    private JTable table;
    private final JScrollPane sp;
    private final JTextField textField = new JTextField("");
    private JButton button = new JButton("Delete");

    public PublicKeyRingView() {
        this.setOpaque(false);
        this.setLayout(new BorderLayout());

        sp = new JScrollPane();
        sp.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        PublicKeyRing.getInstance().addObserver(this);
        setData(PublicKeyRing.getInstance().getAllKeys());

        this.add(sp);
        this.addTopComponents();
    }

    private void addTopComponents() {
        JPanel panel = new JPanel(new GridLayout(2 , 1));

        JPanel panel2 = new JPanel(new GridLayout(1 , 5));
        for (int i = 0 ; i < 2 ; i++) panel2.add(new JPanel());
        panel2.add(button);
        for (int i = 0 ; i < 2 ; i++) panel2.add(new JPanel());

        panel2.setBorder(new EmptyBorder(5,0,5,0));

        button.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row == -1) {
                JOptionPane.showMessageDialog(null,
                        "Select key that you want to delete!",
                        "PopUp Dialog",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            PublicKeyRing.getInstance().removeKey(row);
        });
        panel.add(panel2);
        panel.add(textField);
        textField.setHorizontalAlignment(SwingConstants.CENTER);
        textField.setFont(new Font("Serif", Font.BOLD, 20));
        textField.setEditable(false);
        textField.setBorder(new EmptyBorder(10,10,10,10));
        this.add(panel, BorderLayout.NORTH);
    }

    public void setData(List<PGPPublicKeyRing> pks) {
        if (table != null) this.sp.remove(table);

        String[][] data = new String[pks.size()][8];
        String[] column = {"Timestamp", "Key ID", "Public key", "User Id", "Owner trust", "Key Legitimacy", "Signatures", "Signatures Trust"};
        for (int i = 0; i < pks.size(); i++) {
            PGPPublicKey pk = Utils.getMasterPGPPublicKey(pks.get(i));

            data[i][0] = new SimpleDateFormat("yyyy-MM-dd hh:mm").format(pk.getCreationTime());
            data[i][1] = Utils.getPGPPublicKeyIdBase64(pk);
            data[i][2] = Base64.toBase64String(pk.getPublicKeyPacket().getKey().getEncoded());
            data[i][3] = "";
            Iterator<String> userIDs = pk.getUserIDs();
            if (userIDs.hasNext()) {
                data[i][3] = userIDs.next();
            }

            data[i][4] = "";
            data[i][5] = "";

            data[i][6] = "";
            Iterator<PGPSignature> signatures = pk.getKeySignatures();
            while(signatures.hasNext()) {
                PGPSignature signature = signatures.next();
                data[i][6] += signature.getKeyID() + ",";
            }

            data[i][7] = "";
            Iterator<PGPSignature> signatures2 = pk.getSignatures();
            while(signatures2.hasNext()) {
                PGPSignature signature = signatures2.next();
                data[i][7] += signature.getKeyID() + ",";
            }
        }


        table = new JTable(data, column);
        table.setDefaultEditor(Object.class, null);

        this.sp.setViewportView(table);

        table.setFillsViewportHeight(true);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                super.mouseClicked(e);
                if (e.getClickCount() == 1) {
                    final JTable target = (JTable)e.getSource();
                    final int row = target.getSelectedRow();
                    final int column = target.getSelectedColumn();
                    String value = (String)target.getValueAt(row , column);

                    textField.setText(value);
                }
            }
        });
    }

    @Override
    public void observableChanged(List<PGPPublicKeyRing> pks) {
        setData(pks);
    }
}
