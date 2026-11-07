import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  AppState,
  BackHandler,
  Image,
  Linking,
  Modal,
  Platform,
  Pressable,
  StatusBar,
  Text,
  View,
} from "react-native";
import { WebView, type WebViewNavigation } from "react-native-webview";
import * as Application from "expo-application";
import * as FileSystem from "expo-file-system/legacy";
import * as IntentLauncher from "expo-intent-launcher";
import { SITE_URL, getReleaseInfo, type ReleaseInfo } from "./lib/gs-suraha";

const GREEN = "#315C3B";
const SAFFRON = "#D9822B";
const INK = "#183328";
const SURFACE = "#FFFFFF";

// App-only CSS: the live website is not changed. Both public front-page rows
// are pinned together, and authenticated artwork headers stay pinned as well.
const APP_ONLY_LAYOUT_SCRIPT = `(function(){
  var id='gs-suraha-app-only-layout';
  var css='@media(max-width:900px){html,body,body.authenticated-page,body.authenticated-page #root{margin:0!important;padding:0!important}body.authenticated-page .main,body.authenticated-page .main.page-shell{margin:0!important;padding-top:76px!important}.main>.topbar.topbar-with-artwork,body.authenticated-page .topbar.topbar-with-artwork{position:fixed!important;top:0!important;left:0!important;right:0!important;width:auto!important;margin:0!important;z-index:1000!important}.home-page{padding-top:var(--gs-suraha-front-header-height,0px)!important}.home-page .home-top{position:fixed!important;top:0!important;left:0!important;right:0!important;width:auto!important;margin:0!important;z-index:1100!important}.home-page .home-nav{position:fixed!important;top:var(--gs-suraha-front-top-height,0px)!important;left:0!important;right:0!important;width:auto!important;margin:0!important;z-index:1099!important}.mobile-bottom-nav{position:fixed!important;left:8px!important;right:8px!important;bottom:8px!important;z-index:1101!important}}';
  function apply(){
    if(!document.head)return;
    var s=document.getElementById(id);
    if(!s){s=document.createElement('style');s.id=id;s.textContent=css;document.head.appendChild(s);}
    document.querySelectorAll('body.authenticated-page .topbar.topbar-with-artwork').forEach(function(el){el.style.setProperty('position','fixed','important');el.style.setProperty('top','0px','important');el.style.setProperty('left','0px','important');el.style.setProperty('right','0px','important');});
    var page=document.querySelector('.home-page');
    if(page){
      var top=page.querySelector('.home-top'), nav=page.querySelector('.home-nav');
      if(top&&window.getComputedStyle(top).display!=='none'){top.style.setProperty('position','fixed','important');top.style.setProperty('top','0px','important');top.style.setProperty('left','0px','important');top.style.setProperty('right','0px','important');top.style.setProperty('z-index','1100','important');}
      if(nav){nav.style.setProperty('position','fixed','important');nav.style.setProperty('left','0px','important');nav.style.setProperty('right','0px','important');nav.style.setProperty('z-index','1099','important');}
      var topHeight=top&&window.getComputedStyle(top).display!=='none'?top.getBoundingClientRect().height:0;
      var navHeight=nav&&window.getComputedStyle(nav).display!=='none'?nav.getBoundingClientRect().height:0;
      if(nav) nav.style.setProperty('top',topHeight+'px','important');
      page.style.setProperty('--gs-suraha-front-top-height',topHeight+'px');
      page.style.setProperty('--gs-suraha-front-header-height',(topHeight+navHeight)+'px');
    }
  }
  apply();
  new MutationObserver(apply).observe(document.documentElement,{childList:true,subtree:true});
  window.addEventListener('resize',apply);
  window.addEventListener('load',apply,{once:true});
  document.addEventListener('click',function(e){
    var a=e.target&&e.target.closest?e.target.closest('a'):null;
    var href=a&&a.getAttribute('href')||'';
    if(/^(upi|intent):\/\//i.test(href)){
      e.preventDefault();e.stopPropagation();window.ReactNativeWebView&&window.ReactNativeWebView.postMessage(JSON.stringify({type:'upi',url:href}));return false;
    }
  },true);
  var originalOpen=window.open;
  window.open=function(url){if(typeof url==='string'&&/^(upi|intent):\/\//i.test(url)){window.ReactNativeWebView&&window.ReactNativeWebView.postMessage(JSON.stringify({type:'upi',url:url}));return null;}return originalOpen.apply(window,arguments);};
  return true;
})();true;`;

function toUpiScheme(url: string): string | null {
  if (/^upi:\/\//i.test(url)) return url;
  if (!/^intent:\/\//i.test(url)) return null;
  const payload = url.split("#Intent;")[0].replace(/^intent:\/\//i, "upi://");
  return payload.startsWith("upi://") ? payload : null;
}

function isSiteUrl(raw: string): boolean {
  try {
    const parsed = new URL(raw);
    return parsed.protocol === "https:" && parsed.hostname.toLowerCase() === "gssuraha.byethost7.com";
  } catch {
    return false;
  }
}

export default function App() {
  const webView = useRef<WebView>(null);
  const canGoBack = useRef(false);
  const [loading, setLoading] = useState(true);
  const [webError, setWebError] = useState(false);
  const [release, setRelease] = useState<ReleaseInfo | null>(null);
  const [updateVisible, setUpdateVisible] = useState(false);
  const [mustUpdate, setMustUpdate] = useState(false);
  const [downloadBusy, setDownloadBusy] = useState(false);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [downloadMessage, setDownloadMessage] = useState("");
  const [installError, setInstallError] = useState(false);
  const currentBuild = useMemo(() => Number(Application.nativeBuildVersion ?? "1") || 1, []);

  const checkForUpdate = useCallback(async () => {
    try {
      const latest = await getReleaseInfo();
      setRelease(latest);
      const newer = latest.enabled && latest.versionCode > currentBuild && !!latest.apkUrl;
      setMustUpdate(newer && latest.minimumVersionCode > currentBuild);
      if (newer) setUpdateVisible(true);
    } catch {
      // The website remains available if release metadata is unavailable.
    }
  }, [currentBuild]);

  useEffect(() => {
    void checkForUpdate();
    const subscription = AppState.addEventListener("change", (state) => {
      if (state === "active") void checkForUpdate();
    });
    return () => subscription.remove();
  }, [checkForUpdate]);

  useEffect(() => {
    if (Platform.OS !== "android") return;
    const sub = BackHandler.addEventListener("hardwareBackPress", () => {
      if (updateVisible) {
        if (!mustUpdate) setUpdateVisible(false);
        return true;
      }
      if (canGoBack.current) {
        webView.current?.goBack();
        return true;
      }
      return false;
    });
    return () => sub.remove();
  }, [mustUpdate, updateVisible]);

  const openExternal = useCallback(async (raw: string) => {
    const upi = toUpiScheme(raw);
    try {
      if (upi && Platform.OS === "android") {
        // Use Android's generic VIEW action so the user can choose any
        // installed UPI app; do not preserve a website/package pin.
        await IntentLauncher.startActivityAsync("android.intent.action.VIEW", { data: upi });
      } else {
        await Linking.openURL(upi ?? raw);
      }
    } catch {
      if (upi) {
        try {
          await Linking.openURL(upi);
        } catch {
          Alert.alert("UPI app nahi mila", "PhonePe, Google Pay, Paytm ya BHIM install karke dobara try karein.");
        }
      }
    }
  }, []);

  const handleNavigation = useCallback((request: WebViewNavigation) => {
    const url = request.url;
    if (url === "about:blank" || url.startsWith("javascript:")) return true;
    if (isSiteUrl(url)) return true;
    void openExternal(url);
    return false;
  }, [openExternal]);

  const beginDownload = useCallback(async () => {
    if (!release?.apkUrl || Platform.OS !== "android") {
      setDownloadMessage("APK update Android app par hi install kiya ja sakta hai.");
      return;
    }
    setDownloadBusy(true);
    setDownloadProgress(0);
    setInstallError(false);
    setDownloadMessage("APK download ho raha hai…");
    try {
      const destination = `${FileSystem.cacheDirectory ?? ""}gs-suraha-${release.versionCode}.apk`;
      const task = FileSystem.createDownloadResumable(release.apkUrl, destination, {}, (event) => {
        if (event.totalBytesExpectedToWrite > 0) setDownloadProgress(Math.min(100, Math.round((event.totalBytesWritten / event.totalBytesExpectedToWrite) * 100)));
      });
      const result = await task.downloadAsync();
      if (!result?.uri) throw new Error("APK download was not completed.");
      const contentUri = await FileSystem.getContentUriAsync(result.uri);
      setDownloadMessage("Download complete. Android installer khul raha hai…");
      await IntentLauncher.startActivityAsync("android.intent.action.INSTALL_PACKAGE", { data: contentUri, type: "application/vnd.android.package-archive", flags: 1 });
      setUpdateVisible(false);
    } catch {
      setInstallError(true);
      setDownloadMessage("Install shuru nahi ho paya. Android settings mein 'Install unknown apps' allow karke phir koshish karein.");
    } finally {
      setDownloadBusy(false);
    }
  }, [release]);

  const openInstallPermissionSettings = useCallback(async () => {
    try {
      await IntentLauncher.startActivityAsync(IntentLauncher.ActivityAction.MANAGE_UNKNOWN_APP_SOURCES, { data: `package:${Application.applicationId ?? ""}` });
    } catch {
      await Linking.openSettings();
    }
  }, []);

  const reloadSite = useCallback(() => {
    setWebError(false);
    setLoading(true);
    webView.current?.reload();
    void checkForUpdate();
  }, [checkForUpdate]);

  return (
    <View style={{ flex: 1, backgroundColor: SURFACE }}>
      <StatusBar hidden={false} translucent={false} barStyle="dark-content" backgroundColor="#FFFFFF" />
      {webError ? (
        <View style={{ flex: 1, alignItems: "center", justifyContent: "center", padding: 28, backgroundColor: SURFACE }}>
          <Text style={{ fontSize: 19, fontWeight: "800", color: INK, textAlign: "center" }}>Website abhi load nahi hui</Text>
          <Text style={{ marginTop: 10, color: "#53665A", textAlign: "center", lineHeight: 21 }}>Internet connection check karke dobara koshish karein.</Text>
          <Pressable onPress={reloadSite} style={{ marginTop: 18, paddingHorizontal: 22, paddingVertical: 12, borderRadius: 12, backgroundColor: SAFFRON }}><Text style={{ color: "#fff", fontWeight: "800" }}>Dobara koshish karein</Text></Pressable>
        </View>
      ) : (
        <View style={{ flex: 1 }}>
          {loading && (
            <View pointerEvents="none" style={{ position: "absolute", zIndex: 2, top: 0, left: 0, right: 0, bottom: 0, alignItems: "center", justifyContent: "center", backgroundColor: "#F7FAF8" }}>
              <Image source={require("./assets/images/loading.gif")} style={{ width: 132, height: 132 }} />
            </View>
          )}
          <WebView ref={webView} source={{ uri: SITE_URL }} injectedJavaScriptBeforeContentLoaded={APP_ONLY_LAYOUT_SCRIPT} injectedJavaScript={APP_ONLY_LAYOUT_SCRIPT} originWhitelist={["*"]} javaScriptEnabled domStorageEnabled sharedCookiesEnabled thirdPartyCookiesEnabled setSupportMultipleWindows={false} onMessage={(event) => { try { const message = JSON.parse(event.nativeEvent.data); if (message?.type === "upi" && typeof message.url === "string") void openExternal(message.url); } catch {} }} onShouldStartLoadWithRequest={handleNavigation} onOpenWindow={(event) => { void openExternal(event.nativeEvent.targetUrl); }} onFileDownload={(event) => { void openExternal(event.nativeEvent.downloadUrl); }} onNavigationStateChange={(state) => { canGoBack.current = state.canGoBack; }} onLoadStart={() => { setLoading(true); setWebError(false); }} onLoadEnd={() => setLoading(false)} onError={() => { setLoading(false); setWebError(true); }} style={{ flex: 1, backgroundColor: SURFACE }} />
        </View>
      )}
      <Modal visible={updateVisible} transparent animationType="fade" onRequestClose={() => { if (!mustUpdate) setUpdateVisible(false); }}>
        <View style={{ flex: 1, backgroundColor: "rgba(8, 28, 15, 0.56)", justifyContent: "center", padding: 22 }}>
          <View style={{ borderRadius: 20, padding: 22, backgroundColor: "#fff", borderTopWidth: 5, borderTopColor: SAFFRON }}>
            <Text style={{ fontSize: 21, fontWeight: "900", color: INK }}>Naya app update available</Text>
            <Text style={{ marginTop: 8, color: "#526257", lineHeight: 22 }}>GS Suraha app ka version {release?.versionName} ab available hai.</Text>
            {!!release?.releaseNotes && <Text style={{ marginTop: 10, color: INK, lineHeight: 21 }}>{release.releaseNotes}</Text>}
            {downloadBusy && <View style={{ marginTop: 16 }}><ActivityIndicator color={GREEN} /><Text style={{ marginTop: 8, textAlign: "center", color: GREEN }}>{downloadProgress}% — {downloadMessage}</Text></View>}
            {!downloadBusy && !!downloadMessage && <Text style={{ marginTop: 12, color: installError ? "#9B2C2C" : GREEN, lineHeight: 21 }}>{downloadMessage}</Text>}
            <Pressable disabled={downloadBusy} onPress={beginDownload} style={{ marginTop: 18, padding: 14, borderRadius: 12, backgroundColor: GREEN, alignItems: "center", opacity: downloadBusy ? 0.7 : 1 }}><Text style={{ color: "#fff", fontWeight: "800" }}>{downloadBusy ? "Download ho raha hai…" : "Update download aur install karein"}</Text></Pressable>
            {installError && <Pressable disabled={downloadBusy} onPress={openInstallPermissionSettings} style={{ marginTop: 10, padding: 12, alignItems: "center" }}><Text style={{ color: GREEN, fontWeight: "700" }}>Install permission settings kholen</Text></Pressable>}
            {!mustUpdate && <Pressable disabled={downloadBusy} onPress={() => { setUpdateVisible(false); setDownloadMessage(""); }} style={{ marginTop: 10, padding: 12, alignItems: "center" }}><Text style={{ color: "#5D6B61", fontWeight: "700" }}>Abhi nahi, current app chalayein</Text></Pressable>}
          </View>
        </View>
      </Modal>
    </View>
  );
}
