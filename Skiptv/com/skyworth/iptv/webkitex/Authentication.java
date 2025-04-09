package com.skyworth.iptv.webkitex;

import android.os.SystemProperties;
import android.util.Log;
import com.skyworth.iptv.SkEPGInfo;
import com.skyworth.iptv.Skiptv;
import com.skyworth.iptv.common.SkCommon;
import com.skyworth.iptv.common.SkConfig;
import com.skyworth.iptv.common.SkDebug;
import com.skyworth.iptv.common.SkGlobalKeyMapForHW;
import com.skyworth.iptv.common.SkKeyCodeMap;
import com.skyworth.iptv.common.SkNtpClient;
import com.skyworth.iptv.common.SkServiceEntry;
import com.skyworth.iptv.common.SkiTVParams;
import com.skyworth.iptv.player.ChannelInfo;
import com.skyworth.iptv.player.ChannelInfoParser;
import com.skyworth.iptv.player.SkPlayer;
import com.skyworth.iptv.provider.SkiptvDBHelper;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Random;
import org.chromium.content.browser.PageTransitionTypes;
import org.xwalk.core.JavascriptInterface;

/* loaded from: classes.dex */
public class Authentication {
    private static HashMap<Integer, ChannelInfo> channelList = new HashMap<>();
    private SkiptvDBHelper chProviderHelper;
    private boolean mSetChannelUrlFlag;
    private HashMap<String, String> frontKey = new HashMap<>();
    private SkiTVParams mParams = SkiTVParams.getInstance();
    private int mEncryptType = 0;
    private boolean mGetFlag = false;

    public Authentication() {
        this.chProviderHelper = null;
        this.mSetChannelUrlFlag = false;
        this.frontKey.put("UserID", SkiTVParams.PARAM_NAME_USERNAME);
        this.frontKey.put("STBType", SkiTVParams.PARAM_NAME_PRODUCT_TYPE);
        this.frontKey.put("STBVersion", SkiTVParams.PARAM_NAME_SOFTWARE_VERSION);
        this.frontKey.put("STBID", SkiTVParams.PARAM_NAME_SN);
        this.frontKey.put("AccessUserName", SkiTVParams.PARAM_NAME_USERNAME);
        if (SkConfig.isCustomXJCTC() || SkConfig.isCustomGSCTC()) {
            this.frontKey.put("ntvuseraccount", SkiTVParams.PARAM_NAME_USERNAME);
        }
        if (SkConfig.SYS_PROVIDER_CHLIST) {
            this.chProviderHelper = Skiptv.getDBHelper();
        }
        this.mSetChannelUrlFlag = false;
    }

    private String GetHuaWeiMD5(String original, String key) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(original.getBytes());
            md.update(key.getBytes());
            byte[] buffer = md.digest();
            StringBuffer sb = new StringBuffer();
            for (byte b : buffer) {
                sb.append(Integer.toHexString(b & 255));
            }
            String ret = sb.substring(0, 8);
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private String GetIdentityEncode(String sessionID, String shareKey) {
        String ret = "";
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(sessionID.getBytes());
            md.update(shareKey.getBytes());
            byte[] buffer = md.digest();
            StringBuffer sb = new StringBuffer();
            for (byte b : buffer) {
                sb.append(Integer.toHexString((b & 255) | PageTransitionTypes.PAGE_TRANSITION_QUALIFIER_MASK).substring(6));
            }
            ret = sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret.toUpperCase();
    }

    private String GetGDMD5(String original) {
        String ret = "";
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(original.getBytes());
            byte[] buffer = md.digest();
            StringBuffer sb = new StringBuffer();
            for (byte b : buffer) {
                sb.append(Integer.toHexString(b & 255));
            }
            ret = sb.substring(0, 24);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret.toUpperCase();
    }

    public String GetAuthInfo(String EncryToken, String CustomStr) {
        Debug("GetAuthInfo, EncryToken:" + EncryToken + ", CustomStr:" + CustomStr);
        Random rnd = new Random(System.currentTimeMillis());
        long random = rnd.nextInt(100000000);
        String username = this.mParams.Username();
        String sn = this.mParams.Sn();
        String ip = this.mParams.Ip();
        String mac = this.mParams.Mac();
        if ((username.equals("") || sn.equals("") || mac.equals("")) && !this.mParams.hasSkParam()) {
            Skiptv.sendMessage(Skiptv.EVENT_SHOW_SETTING);
            return "";
        }
        String strEncry = String.valueOf(random) + "$" + EncryToken;
        String strEncry2 = ((((strEncry + "$" + username) + "$" + sn) + "$" + ip) + "$" + mac) + "$" + CustomStr;
        String password = this.mParams.Password();
        String encryptKey = null;
        if (this.mEncryptType == 2) {
            encryptKey = GetHuaWeiMD5(password, "99991231");
        } else if (this.mEncryptType == 3) {
            encryptKey = GetGDMD5(password);
        }
        if (encryptKey == null) {
            encryptKey = password;
        }
        String strRet = SkCommon.Union3DesEncrypt(strEncry2, encryptKey);
        return strRet;
    }

    @JavascriptInterface
    public String CTCGetAuthInfo(String EncryToken) {
        Debug("CTCGetAuthInfo, EncryToken:" + EncryToken);
        return GetAuthInfo(EncryToken, "$CTC");
    }

    @JavascriptInterface
    public boolean CTCSetConfig(String key, String value) {
        return CTCSetConfig(key, value, false);
    }

    public boolean CTCSetConfig(String key, String value, boolean isRevert) {
        if (!key.equalsIgnoreCase("EPGDomain")) {
            if (!key.equalsIgnoreCase(SkConfig.BROWSER_LOGIN_TOKENNAME)) {
                if (!key.equalsIgnoreCase("ChannelCount")) {
                    if (!key.equalsIgnoreCase("Channel")) {
                        if (!key.equalsIgnoreCase("resignon")) {
                            if (!key.equalsIgnoreCase("ServiceEntry")) {
                                if (!key.equalsIgnoreCase("EPGGroupNMB")) {
                                    if (!key.equalsIgnoreCase("exitIptvApp")) {
                                        if (!key.equalsIgnoreCase("epg_info")) {
                                            if (!key.equalsIgnoreCase("EncryptionType")) {
                                                if (!key.equalsIgnoreCase(SkiTVParams.PARAM_NAME_TR069_SERVER) && !key.equalsIgnoreCase(SkiTVParams.PARAM_NAME_TR069_SERVER2)) {
                                                    if (!key.equalsIgnoreCase("SetEpgMode")) {
                                                        if (!key.equalsIgnoreCase("TransportProtocol")) {
                                                            if (!key.equalsIgnoreCase("PADBootLogPicURL") && !key.equalsIgnoreCase("PADAuthenBackgroundPicURL")) {
                                                                if (!key.equalsIgnoreCase("GlobalKeyTable")) {
                                                                    if (!key.equalsIgnoreCase("Pwd") || !SkConfig.isCustomMatch("ln-cu")) {
                                                                        if (!key.equalsIgnoreCase("UserID") || !SkConfig.isCustomMatch("ln-cu")) {
                                                                            if (!key.equalsIgnoreCase("authStatus")) {
                                                                                if (!key.equalsIgnoreCase("EPGError")) {
                                                                                    if (key.equalsIgnoreCase("FrameError")) {
                                                                                        Debug("FrameError:" + value);
                                                                                        Skiptv.sendMessage(Skiptv.EVENT_PAGE_FRAMEERR_CODE, value);
                                                                                    }
                                                                                } else {
                                                                                    Debug("EPGError:" + value);
                                                                                    Skiptv.sendMessage(Skiptv.EVENT_PAGE_EPGERR_CODE, value);
                                                                                }
                                                                            } else {
                                                                                this.mParams.setParam("authStatus", value);
                                                                            }
                                                                        } else {
                                                                            Debug("chenlei add for ln_cu , UserID:" + value);
                                                                            this.mParams.setParam(SkiTVParams.PARAM_NAME_USERNAME, value.toString());
                                                                        }
                                                                    } else {
                                                                        Debug("chenlei add for ln_cu , Pwd:" + value);
                                                                        this.mParams.setParam(SkiTVParams.PARAM_NAME_PASSWORD, value.toString());
                                                                    }
                                                                } else {
                                                                    Debug("lgl add for hlj_cu GlobalKeyTable");
                                                                    SkGlobalKeyMapForHW.registerGlobalKey(value);
                                                                }
                                                            } else if (SkConfig.isCustomZJCTC()) {
                                                                Skiptv.sendMessage(Skiptv.EVENT_UPGRADE_BOOT_AND_AUTHEN_PICTURE, value.toString());
                                                                return true;
                                                            }
                                                        } else {
                                                            Debug("TransportProtocol = fuck---" + value);
                                                        }
                                                    } else if (SkConfig.isCustomMatch("js-ctc")) {
                                                        if (value.equalsIgnoreCase("720P")) {
                                                            SkEPGInfo epg = new SkEPGInfo();
                                                            epg.setWidth(1280);
                                                            epg.setHeight(720);
                                                            Skiptv.sendMessage(Skiptv.EVENT_PAGE_RESET_EPGSIZE, epg);
                                                        }
                                                        return true;
                                                    }
                                                } else {
                                                    if (!value.equals("")) {
                                                        this.mParams.setParam(key, value.toString());
                                                    }
                                                    return true;
                                                }
                                            } else if (value.equals("0002")) {
                                                this.mEncryptType = 2;
                                            } else if (value.equals("0003")) {
                                                this.mEncryptType = 3;
                                            } else {
                                                this.mEncryptType = 0;
                                            }
                                        } else {
                                            Debug("received epg_info!!!!!!" + value);
                                            if (SkConfig.isCustomZJCTC()) {
                                                SkServiceEntry.SkServiceEntryItem home_page = SkServiceEntry.get(SkKeyCodeMap.homeKey());
                                                if (home_page != null) {
                                                    Skowb.getSkowbInstance().skFirstPageUrl(home_page.Url());
                                                } else {
                                                    Skowb.getSkowbInstance().skFirstPageUrl("skyworth::null");
                                                }
                                            }
                                            Skiptv.sendMessage(Skiptv.EVENT_SET_EPGINFO, value);
                                        }
                                    } else {
                                        Debug("received exitIptvApp!!!!!!");
                                        if (SkConfig.isCustomMatch("zjwz-ctc")) {
                                            Skiptv.sendMessage(Skiptv.EVENT_GOTO_ZJ_SMART_HOME);
                                        } else {
                                            Skiptv.sendMessage(Skiptv.EVENT_GOTO_BACKROUNT);
                                        }
                                        return true;
                                    }
                                } else {
                                    if (SkConfig.isCustomMatch("cq-ctc") && (value.equals("2") || value.equals("6"))) {
                                        SkConfig.BROWSER_SEND_KEY_ONCE = true;
                                    }
                                    if (SkConfig.isCustomMatch("sn-ctc") && (value.endsWith("gqftkdb") || value.equals("xagqftkdb") || value.equals("bestvgqkdb") || value.equals("kjxx"))) {
                                        SkConfig.BROWSER_SEND_KEY_ONCE = false;
                                    }
                                }
                            } else {
                                Debug("ServiceEntry");
                                String SqmEpgIp = "";
                                if (value != null) {
                                    try {
                                        if (value.length() != 0) {
                                            SqmEpgIp = value.lastIndexOf(":") > value.indexOf(":") ? value.substring(value.indexOf("//") + 2, value.lastIndexOf(":")) : value.substring(value.indexOf("//") + 2, value.indexOf("/", value.indexOf("//") + 3));
                                        }
                                    } catch (Exception e) {
                                        Log.d("sktest", "value parse fail" + value);
                                    }
                                }
                                SystemProperties.set("persist.sys.sqm.epgip", SqmEpgIp);
                                SkServiceEntry.add(value);
                                if (!isRevert) {
                                    this.mParams.addTempList(key, value);
                                }
                                return true;
                            }
                        } else {
                            SkConfig.DO_EPG_RECOVERY = false;
                            Skiptv.sendMessage(100);
                            return true;
                        }
                    } else {
                        if (!isRevert) {
                            this.mParams.addTempList(key, value);
                        }
                        if (SkConfig.EPG_RECOVERY) {
                            SkWebView wv = Skiptv.getWebView();
                            if (wv != null && !this.mSetChannelUrlFlag) {
                                this.mSetChannelUrlFlag = true;
                                Skiptv.sendMessage(Skiptv.EVENT_PAGE_CONNECT_HOMEPAGE_FAIL);
                            }
                        }
                        ChannelInfo channel = new ChannelInfo(value, new ChannelInfoParser() { // from class: com.skyworth.iptv.webkitex.Authentication.1
                            @Override // com.skyworth.iptv.player.ChannelInfoParser
                            public boolean parseChannel(String tmp, ChannelInfo channel2) {
                                String[] token = tmp.split("\",");
                                for (String s : token) {
                                    String[] kv = s.split("=\"");
                                    String chlistVal = "";
                                    if (kv.length >= 2) {
                                        if ("".equals(kv[1]) || "null".equals(kv[1])) {
                                            chlistVal = "0";
                                        } else {
                                            chlistVal = kv[1].trim();
                                        }
                                    }
                                    try {
                                        String chlistKey = kv[0].trim();
                                        if ("ChannelID".equalsIgnoreCase(chlistKey)) {
                                            channel2.setChannelID(chlistVal);
                                        } else if ("ChannelName".equalsIgnoreCase(chlistKey)) {
                                            channel2.setChannelName(chlistVal);
                                        } else if ("ChannelURL".equalsIgnoreCase(chlistKey)) {
                                            channel2.setChannelURL(chlistVal);
                                        } else if ("ChannelSDP".equalsIgnoreCase(chlistKey)) {
                                            channel2.setChannelSDP(chlistVal);
                                        } else if ("TimeShiftURL".equalsIgnoreCase(chlistKey)) {
                                            channel2.setTimeShiftURL(chlistVal);
                                        } else if ("ChannelLogURL".equalsIgnoreCase(chlistKey)) {
                                            channel2.setChannelLogURL(chlistVal);
                                        } else if ("ChannelPurchased".equalsIgnoreCase(chlistKey)) {
                                            channel2.setChannelPurchased(chlistVal);
                                        } else if ("used".equalsIgnoreCase(chlistKey)) {
                                            channel2.setUsed(Integer.parseInt(chlistVal));
                                        } else if ("UserChannelID".equalsIgnoreCase(chlistKey)) {
                                            channel2.setUserChannelID(Integer.parseInt(chlistVal));
                                        } else if ("TimeShift".equalsIgnoreCase(chlistKey)) {
                                            channel2.setTimeShift(Integer.parseInt(chlistVal));
                                        } else if ("TimeShiftLength".equalsIgnoreCase(chlistKey)) {
                                            channel2.setTimeShiftLength(Integer.parseInt(chlistVal));
                                        } else if ("PositionX".equalsIgnoreCase(chlistKey)) {
                                            channel2.setPositionX(Integer.parseInt(chlistVal));
                                        } else if ("PositionY".equalsIgnoreCase(chlistKey)) {
                                            channel2.setPositionY(Integer.parseInt(chlistVal));
                                        } else if ("BeginTime".equalsIgnoreCase(chlistKey)) {
                                            channel2.setBeginTime(Integer.parseInt(chlistVal));
                                        } else if ("Interval".equalsIgnoreCase(chlistKey)) {
                                            channel2.setInterval(Integer.parseInt(chlistVal));
                                        } else if ("Lasting".equalsIgnoreCase(chlistKey)) {
                                            channel2.setLasting(Integer.parseInt(chlistVal));
                                        } else if ("ChannelType".equalsIgnoreCase(chlistKey)) {
                                            channel2.setChannelType(Integer.parseInt(chlistVal));
                                        } else if (SkConfig.SYS_CUSTOM_REGION.equalsIgnoreCase("sd-cu")) {
                                            if ("ChannelFCCServerAddr".equalsIgnoreCase(chlistKey)) {
                                                channel2.setChannelFCCServerAddr(chlistVal);
                                            } else if ("ChannelFccAgentAddr".equalsIgnoreCase(chlistKey)) {
                                                channel2.setChannelFccAgentAddr(chlistVal);
                                            } else if ("ChannelFCCIP".equalsIgnoreCase(chlistKey)) {
                                                channel2.setChannelFCCIP(chlistVal);
                                            } else if ("ChannelFCCPort".equalsIgnoreCase(chlistKey)) {
                                                channel2.setChannelFCCPort(chlistVal);
                                            }
                                        }
                                    } catch (Exception e2) {
                                        e2.printStackTrace();
                                    }
                                }
                                return true;
                            }
                        });
                        if (SkConfig.isCustomMatch("js-ctc") || SkConfig.isCustomMatch("xj-ctc") || SkConfig.isCustomMatch("sd-cu")) {
                            String chInfo = String.format("UserChannelID:\"%s\", ChannelName:\"%s\", ChannelURL:\"%s\", TimeShiftURL:\"%s\"", Integer.valueOf(channel.getUserChannelID()), channel.getChannelName(), channel.getChannelURL(), channel.getTimeShiftURL());
                            this.mParams.addChInfo(chInfo);
                        }
                        if (SkConfig.isCustomMatch("sd-cu")) {
                            String userChId = String.valueOf(channel.getChannelID());
                            String chNo = String.valueOf(channel.getUserChannelID());
                            this.mParams.addChannelInfo(userChId, chNo, channel.getChannelName(), "");
                        }
                        if (SkConfig.SYS_PROVIDER_CHLIST && this.chProviderHelper != null) {
                            this.chProviderHelper.addChannel(channel.getUserChannelID(), channel.getChannelName());
                        }
                        setChannelInfo(Integer.valueOf(channel.getUserChannelID()), channel);
                        return true;
                    }
                } else if (SkConfig.SYS_PROVIDER_CHLIST && this.chProviderHelper != null) {
                    this.chProviderHelper.clearChannels();
                }
            } else {
                Skiptv.sendMessage(Skiptv.EVENT_PAGE_FRONT_LOGINED);
            }
        } else {
            Skiptv.sendMessage(4, value);
            SkServiceEntry.setEPGDomain(value);
        }
        if (!isRevert) {
            this.mParams.setTemp(key, value.toString());
        }
        this.mParams.setParam(key, value.toString());
        if (key.equalsIgnoreCase(SkiTVParams.PARAM_NAME_NTP_SERVER) || key.equalsIgnoreCase(SkiTVParams.PARAM_NAME_NTP_SERVER2)) {
            SkNtpClient.NtpTiming();
        }
        if (key.equalsIgnoreCase(SkiTVParams.PARAM_NAME_UPGRADE_SERVER) || key.equalsIgnoreCase(SkiTVParams.PARAM_NAME_UPGRADE_SERVER2)) {
            CTCStartUpdate();
        }
        return true;
    }

    @JavascriptInterface
    public String CTCGetConfig(String key) {
        Log.d("lgl", "CTCGetConfig key is:" + key);
        if (key.equalsIgnoreCase("isSmartHomeSTB") || key.equalsIgnoreCase("SupportHD")) {
            return "1";
        }
        if (key.equalsIgnoreCase("UserField")) {
            return SkConfig.EPG_USERFIELD_VAL;
        }
        if (key.equalsIgnoreCase("identityEncode")) {
            String sessionID = this.mParams.getParam("SessionID");
            String shareKey = this.mParams.getParam("shareKey");
            return GetIdentityEncode(sessionID, shareKey);
        }
        if (key.equalsIgnoreCase("PADBootLogPicURL")) {
            return this.mParams.getSysParam("skyworth.params.sys.bootlogo_update_url");
        }
        if (key.equalsIgnoreCase("PADAuthenBackgroundPicURL")) {
            return this.mParams.getSysParam("skyworth.params.sys.authenbg_update_url");
        }
        if (key.equals("AudioChannel")) {
            return SkPlayer.getInstance().getCurrentAudioChannel();
        }
        if (key.equals("DirectPlay")) {
            Log.d("lgl", "SYS_CUSTOM_REGION=" + SkConfig.SYS_CUSTOM_REGION);
            if (SkConfig.SYS_CUSTOM_REGION.equalsIgnoreCase("sd-cu")) {
                Log.d("lgl", "mGetFlag=" + this.mGetFlag);
                if (!this.mGetFlag) {
                    this.mGetFlag = true;
                    String isHotel = SystemProperties.get("persist.sys.hotel.flag");
                    Log.d("lgl", "isHotel=" + isHotel);
                    if (isHotel != null && isHotel.equals("1")) {
                        return "1";
                    }
                    return "0";
                }
            }
        } else if (key.equalsIgnoreCase("LastChannelNo")) {
            Log.d("lgl", "SYS_CUSTOM_REGION=" + SkConfig.SYS_CUSTOM_REGION);
            if (SkConfig.SYS_CUSTOM_REGION.equalsIgnoreCase("sd-cu")) {
                String isHotel2 = SystemProperties.get("persist.sys.hotel.flag");
                Log.d("lgl", "isHotel=" + isHotel2);
                if (isHotel2 != null && isHotel2.equals("1")) {
                    return SystemProperties.get("persist.sys.hotel.lastChanNum");
                }
                return "0";
            }
        }
        String ret = this.mParams.getParam(key);
        if ((ret == null || ret.equals("")) && this.frontKey.containsKey(key)) {
            ret = this.mParams.getParam(this.frontKey.get(key));
        }
        if (ret == null || ret.equals("")) {
            if (key.equalsIgnoreCase("Lang")) {
                if (SkConfig.isCustomMatch("jl-cu")) {
                    return "1";
                }
                return "0";
            }
            if (key.equalsIgnoreCase("ConnectType") || key.equalsIgnoreCase("AccessMethod")) {
                return "dhcp";
            }
            if (key.equalsIgnoreCase("templateName")) {
                return "default";
            }
            if (key.equalsIgnoreCase("areaid") || key.equalsIgnoreCase("UserGroupNMB") || key.equalsIgnoreCase("PackageIDs")) {
                return "";
            }
            return ret;
        }
        return ret;
    }

    @JavascriptInterface
    public boolean CTCStartUpdate() {
        Debug("CTCStartUpdate");
        return true;
    }

    @JavascriptInterface
    public String OTVGetAuthInfo(String EncryToken) {
        Debug("OTVGetAuthInfo, EncryToken:" + EncryToken);
        return GetAuthInfo(EncryToken, "CM");
    }

    @JavascriptInterface
    public boolean OTVSetConfig(String key, String value) {
        return CTCSetConfig(key, value);
    }

    @JavascriptInterface
    public String OTVGetConfig(String key) {
        return CTCGetConfig(key);
    }

    @JavascriptInterface
    public boolean OTVStartUpdate() {
        return CTCStartUpdate();
    }

    @JavascriptInterface
    public String CUGetAuthInfo(String EncryToken) {
        Debug("CUGetAuthInfo, EncryToken:" + EncryToken);
        return GetAuthInfo(EncryToken, "$CTC");
    }

    @JavascriptInterface
    public boolean CUSetConfig(String key, String value) {
        return CTCSetConfig(key, value);
    }

    @JavascriptInterface
    public String CUGetConfig(String key) {
        return CTCGetConfig(key);
    }

    @JavascriptInterface
    public boolean CUStartUpdate() {
        return CTCStartUpdate();
    }

    public static void setChannelInfo(Integer key, ChannelInfo channel) {
        channelList.put(key, channel);
    }

    public static ChannelInfo getChannelInfo(Integer key) {
        if (channelList.containsKey(key)) {
            return channelList.get(key);
        }
        return null;
    }

    private void Debug(String msg) {
        if (SkConfig.DEBUG_AUTHENTICATION) {
            SkDebug.Debug("Authentication", msg);
        }
    }
}
