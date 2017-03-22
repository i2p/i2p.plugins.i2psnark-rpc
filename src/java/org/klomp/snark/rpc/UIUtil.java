package org.klomp.snark.rpc;

import java.io.File;
import java.io.IOException;

import net.i2p.data.DataHelper;

import org.klomp.snark.PeerID;

/**
 * From I2PSnarkServlet
 * TODO put in common dir
 */
class UIUtil {

    private UIUtil() {}

    /**
     *  @param pid may be null
     *  @return "Name w.x.y.z" or "Name"
     *  @since 0.9.30
     */
    public static String getClientName(PeerID pid) {
        String ch = pid != null ? pid.toString().substring(0, 4) : "????";
        String client;
        if ("AwMD".equals(ch))
            client = "I2PSnark";
        else if ("BFJT".equals(ch))
            client = "I2PRufus";
        else if ("TTMt".equals(ch))
            client = "I2P-BT";
        else if ("LUFa".equals(ch))
            client = "Vuze" + getAzVersion(pid.getID());
        else if ("CwsL".equals(ch))
            client = "I2PSnarkXL";
        else if ("LVhE".equals(ch))
            client = "XD" + getAzVersion(pid.getID());
        else if ("ZV".equals(ch.substring(2,4)) || "VUZP".equals(ch))
            client = "Robert" + getRobtVersion(pid.getID());
        else if (ch.startsWith("LV")) // LVCS 1.0.2?; LVRS 1.0.4
            client = "Transmission" + getAzVersion(pid.getID());
        else if ("LUtU".equals(ch))
            client = "KTorrent" + getAzVersion(pid.getID());
        else
            client = "Unknown (" + ch + ')';
        return client;
    }

    /**
     *  Get version from bytes 3-6
     *  @return " w.x.y.z" or ""
     *  @since 0.9.14
     */
    private static String getAzVersion(byte[] id) {
        if (id[7] != '-')
            return "";
        StringBuilder buf = new StringBuilder(16);
        buf.append(' ');
        for (int i = 3; i <= 6; i++) {
            int val = id[i] - '0';
            if (val < 0)
                return "";
            if (val > 9)
                val = id[i] - 'A';
            if (i != 6 || val != 0) {
                if (i != 3)
                    buf.append('.');
                buf.append(val);
            }
        }
        return buf.toString();
    }

    /**
     *  Get version from bytes 3-5
     *  @return " w.x.y" or ""
     *  @since 0.9.14
     */
    private static String getRobtVersion(byte[] id) {
        StringBuilder buf = new StringBuilder(8);
        buf.append(' ');
        for (int i = 3; i <= 5; i++) {
            int val = id[i];
            if (val < 0)
                return "";
            if (i != 3)
                buf.append('.');
            buf.append(val);
        }
        return buf.toString();
    }

    /**
     *  Is "a" equal to "b",
     *  or is "a" a directory and a parent of file or directory "b",
     *  canonically speaking?
     *
     *  @since 0.9.15
     */
    public static boolean isParentOf(File a, File b) {
        try {
            a = a.getCanonicalFile();
            b = b.getCanonicalFile();
        } catch (IOException ioe) {
            return false;
        }
        if (a.equals(b))
            return true;
        if (!a.isDirectory())
            return false;
        // easy case
        if (!b.getPath().startsWith(a.getPath()))
            return false;
        // dir by dir
        while (!a.equals(b)) {
            b = b.getParentFile();
            if (b == null)
                return false;
        }
        return true;
    }
    
    /**
     * This is for a full URL. For a path only, use encodePath().
     * @since 0.7.14
     */
    static String urlify(String s) {
        return urlify(s, 100);
    }
    
    /**
     * This is for a full URL. For a path only, use encodePath().
     * @since 0.9
     */
    private static String urlify(String s, int max) {
        StringBuilder buf = new StringBuilder(256);
        // browsers seem to work without doing this but let's be strict
        String link = urlEncode(s);
        String display;
        if (s.length() <= max)
            display = DataHelper.escapeHTML(link);
        else
            display = DataHelper.escapeHTML(s.substring(0, max)) + "&hellip;";
        buf.append("<a href=\"").append(link).append("\">").append(display).append("</a>");
        return buf.toString();
    }
    
    /**
     * This is for a full URL. For a path only, use encodePath().
     * @since 0.8.13
     */
    private static String urlEncode(String s) {
        return s.replace(";", "%3B").replace("&", "&amp;").replace(" ", "%20")
                .replace("<", "%3C").replace(">", "%3E")
                .replace("[", "%5B").replace("]", "%5D");
    }
}
