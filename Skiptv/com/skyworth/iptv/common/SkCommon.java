package com.skyworth.iptv.common;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import com.google.common.base.Ascii;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import org.chromium.content.browser.PageTransitionTypes;

/* loaded from: classes.dex */
public class SkCommon {
    private static final int DES_KEY_MIN_LEN = 24;
    private static final char[] MD_HEX_DIGITS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    private SkCommon() {
    }

    public static byte[] hex2byte(String str) {
        int len = str.length();
        byte[] bt = new byte[len / 2];
        for (int n = 0; n < len / 2; n++) {
            String stmp = str.substring(n * 2, (n * 2) + 2);
            bt[n] = (byte) Integer.parseInt(stmp, 16);
        }
        return bt;
    }

    public static String byte2hex(byte[] b) {
        String hs = "";
        for (int n = 0; n < b.length; n++) {
            String stmp = Integer.toHexString(b[n] & 255);
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
            if (n < b.length - 1) {
                hs = hs + "";
            }
        }
        return hs.toUpperCase();
    }

    public static String Union3DesEncrypt(String strMsg, String strKey) {
        String ret = "";
        try {
            int keyappend = 24 - strKey.length();
            for (int i = 0; i < keyappend; i++) {
                strKey = strKey + '0';
            }
            DESedeKeySpec ks = new DESedeKeySpec(strKey.getBytes());
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede");
            SecretKey ky = kf.generateSecret(ks);
            Cipher c = Cipher.getInstance("DESede");
            c.init(1, ky);
            ret = byte2hex(c.doFinal(strMsg.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        Debug("3DES ret:" + ret);
        return ret;
    }

    public static String formatTimeStamp(String pattern, long date) {
        if (pattern.length() == 0) {
            pattern = "yyyy-MM-dd HH:mm:ss";
        }
        Calendar nowDate = new GregorianCalendar();
        nowDate.setTimeInMillis(date);
        SimpleDateFormat df = new SimpleDateFormat(pattern);
        return df.format(nowDate.getTime());
    }

    public static String getLocalIPAddress() {
        String ret = "";
        String pppAddr = "";
        String ethAddr = "";
        String wlanAddr = "";
        try {
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            while (en.hasMoreElements()) {
                NetworkInterface intf = en.nextElement();
                String addr = "";
                Enumeration<InetAddress> enumIPAddr = intf.getInetAddresses();
                while (enumIPAddr.hasMoreElements()) {
                    InetAddress inetAddress = enumIPAddr.nextElement();
                    if (!inetAddress.isLoopbackAddress() && (inetAddress instanceof Inet4Address)) {
                        addr = inetAddress.getHostAddress().toString();
                    }
                }
                if (!addr.isEmpty()) {
                    if (ethAddr.isEmpty() && intf.getName().startsWith("eth")) {
                        ethAddr = addr;
                    } else if (pppAddr.isEmpty() && intf.getName().startsWith("ppp")) {
                        pppAddr = addr;
                    } else if (wlanAddr.isEmpty() && intf.getName().startsWith("wlan")) {
                        wlanAddr = addr;
                    } else {
                        ret = addr;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (wlanAddr != null && !wlanAddr.isEmpty()) {
            ret = wlanAddr;
        }
        if (ethAddr != null && !ethAddr.isEmpty()) {
            ret = ethAddr;
        }
        if (pppAddr != null && !pppAddr.isEmpty()) {
            return pppAddr;
        }
        return ret;
    }

    public static int getStringCheckSum(String str) {
        int ret = 0;
        byte[] number = str.getBytes();
        for (byte b : number) {
            ret += b;
        }
        return ret;
    }

    public static String getKeyValue(String key, String str) {
        try {
            if (str.indexOf(key) < 0) {
                return "";
            }
            int start = str.indexOf(key) + key.length();
            int end = str.length();
            if (str.charAt(start) == '\"') {
                start++;
            }
            for (int i = start; i < str.length(); i++) {
                if (str.charAt(i) == 0 || str.charAt(i) == '\n' || str.charAt(i) == '\r' || str.charAt(i) == '\"') {
                    end = i;
                    break;
                }
            }
            String ret = str.substring(start, end);
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static void installAPK(final String apkPath, final Context context) {
        Runnable rb = new Runnable() { // from class: com.skyworth.iptv.common.SkCommon.1
            @Override // java.lang.Runnable
            public void run() {
                Intent intent = new Intent("android.intent.action.VIEW");
                intent.addFlags(PageTransitionTypes.PAGE_TRANSITION_CHAIN_START);
                intent.setDataAndType(Uri.fromFile(new File(apkPath)), "application/vnd.android.package-archive");
                context.startActivity(intent);
            }
        };
        new Thread(rb).start();
        System.exit(0);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0022 A[Catch: IOException -> 0x0027, LOOP:0: B:5:0x001b->B:7:0x0022, LOOP_END, TRY_LEAVE, TryCatch #0 {IOException -> 0x0027, blocks: (B:16:0x000c, B:18:0x0030, B:5:0x001b, B:7:0x0022, B:3:0x0014), top: B:15:0x000c }] */
    /* JADX WARN: Removed duplicated region for block: B:8:0x002b A[EDGE_INSN: B:8:0x002b->B:9:0x002b BREAK  A[LOOP:0: B:5:0x001b->B:7:0x0022], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String InputStream2String(java.io.InputStream r7, java.lang.String r8) {
        /*
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            r6 = 1024(0x400, float:1.435E-42)
            char[] r0 = new char[r6]
            r4 = 0
            if (r8 == 0) goto L14
            java.lang.String r6 = ""
            boolean r6 = r8.equals(r6)     // Catch: java.io.IOException -> L27
            if (r6 == 0) goto L30
        L14:
            java.io.InputStreamReader r5 = new java.io.InputStreamReader     // Catch: java.io.IOException -> L27
            r5.<init>(r7)     // Catch: java.io.IOException -> L27
            r4 = r5
        L1a:
            r3 = 0
        L1b:
            int r3 = r4.read(r0)     // Catch: java.io.IOException -> L27
            r6 = -1
            if (r3 == r6) goto L2b
            r6 = 0
            r1.append(r0, r6, r3)     // Catch: java.io.IOException -> L27
            goto L1b
        L27:
            r2 = move-exception
            r2.printStackTrace()
        L2b:
            java.lang.String r6 = r1.toString()
            return r6
        L30:
            java.io.InputStreamReader r5 = new java.io.InputStreamReader     // Catch: java.io.IOException -> L27
            r5.<init>(r7, r8)     // Catch: java.io.IOException -> L27
            r4 = r5
            goto L1a
        */
        throw new UnsupportedOperationException("Method not decompiled: com.skyworth.iptv.common.SkCommon.InputStream2String(java.io.InputStream, java.lang.String):java.lang.String");
    }

    public static InputStream String2InputStream(String str, String charSet) {
        if (charSet == null || charSet.equals("")) {
            ByteArrayInputStream stream = new ByteArrayInputStream(str.getBytes());
            return stream;
        }
        try {
            ByteArrayInputStream stream2 = new ByteArrayInputStream(str.getBytes(charSet));
            return stream2;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean deleteFiles(File file) {
        String[] files;
        if (file != null) {
            try {
                if (file.exists() && file.isDirectory() && (files = file.list()) != null) {
                    for (String str : files) {
                        File f = new File(file, str);
                        if (!deleteFiles(f)) {
                            Debug(f.getPath() + " delete failed!");
                        }
                    }
                }
            } catch (SecurityException e) {
                return false;
            }
        }
        if (file != null) {
            file.delete();
        }
        return true;
    }

    public static String toHexString(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            sb.append(MD_HEX_DIGITS[(b[i] & 240) >>> 4]);
            sb.append(MD_HEX_DIGITS[b[i] & Ascii.SI]);
        }
        return sb.toString();
    }

    public static String MDString(String s) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(s.getBytes());
            byte[] messageDigest = digest.digest();
            return toHexString(messageDigest);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String MDString(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(bytes);
            byte[] messageDigest = digest.digest();
            return toHexString(messageDigest);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String MDFile(File file) {
        try {
            byte[] fileBytes = new byte[(int) file.length()];
            InputStream is = new FileInputStream(file);
            is.read(fileBytes);
            is.close();
            return MDString(fileBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String getAssetsContent(Context context, String file) {
        return getAssetsContent(context, file, null);
    }

    public static String getAssetsContent(Context context, String file, String charSet) {
        try {
            InputStream stream = context.getResources().getAssets().open(file);
            String ret = InputStream2String(stream, charSet);
            stream.close();
            return ret;
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String getUrlParam(String url, String paramName) {
        String ret = "";
        if (url != null && paramName != null) {
            try {
                int querySignStart = url.indexOf("?");
                if (querySignStart != -1) {
                    String strQuery = url.substring(querySignStart + 1);
                    String[] params = strQuery.split("&");
                    int len$ = params.length;
                    int i$ = 0;
                    while (true) {
                        if (i$ >= len$) {
                            break;
                        }
                        String s = params[i$];
                        String[] paramPair = s.split("=");
                        if (paramPair.length >= 2) {
                            String name = paramPair[0].trim();
                            String value = paramPair[1].trim();
                            if (name.equalsIgnoreCase(paramName)) {
                                ret = value;
                                break;
                            }
                        }
                        i$++;
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return ret;
        }
        return "";
    }

    public static void Debug(String msg) {
        if (SkConfig.DEBUG_COMMON) {
            SkDebug.Debug("COMMON", msg);
        }
    }
}
