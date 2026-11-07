#!/usr/bin/env python3
"""Prepare a non-destructive PHP patch from the supplied GS Suraha ZIP."""
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("archive", type=Path, help="Path to GS_SURAHA_DESKTOP_PAYMENT_FIX.zip")
parser.add_argument("--output", type=Path, default=Path("website-patch"), help="Patch output directory")
args = parser.parse_args()
ZIP_PATH = args.archive
OUT = args.output

ROUTES = r'''// Public read-only metadata consumed by the Android app. No member/payment data is returned.
if ($route === 'app-update-check') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    $releaseFile = basename(getSetting('app_update_apk_filename', ''));
    $releasePath = $releaseFile !== '' ? __DIR__ . '/uploads/app-releases/' . $releaseFile : '';
    $hasApk = $releasePath !== '' && is_file($releasePath);
    $release = [
        'enabled' => getSetting('app_update_enabled', '0') === '1' && $hasApk,
        'versionName' => getSetting('app_update_version_name', '1.0.0'),
        'versionCode' => max(1, (int)getSetting('app_update_version_code', '1')),
        'minimumVersionCode' => max(1, (int)getSetting('app_update_min_version_code', '1')),
        'apkUrl' => $hasApk ? siteBaseUrl() . '/?route=app-release-download' : '',
        'releaseNotes' => getSetting('app_update_release_notes', ''),
        'logoUrl' => assetUrl(brandingAssetSetting('header_logo', 'assets/logo.png')),
    ];
    echo json_encode($release, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// APK downloads use a server-controlled basename; the APK files are never served from arbitrary paths.
if ($route === 'app-release-download') {
    $releaseFile = basename(getSetting('app_update_apk_filename', ''));
    $releasePath = $releaseFile !== '' ? __DIR__ . '/uploads/app-releases/' . $releaseFile : '';
    if ($releasePath === '' || !is_file($releasePath)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        exit('GS Suraha APK is not available yet.');
    }
    header('Content-Type: application/vnd.android.package-archive');
    header('Content-Disposition: attachment; filename="GS-Suraha.apk"');
    header('Content-Length: ' . filesize($releasePath));
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('X-Content-Type-Options: nosniff');
    readfile($releasePath);
    exit;
}

// Release management is restricted to the existing Super Admin account.
if ($route === 'app-release-admin') {
    requireRole(['admin']);
    if (!isSuperAdmin()) { http_response_code(403); exit('Super Admin permission required'); }
    $msg = '';
    $err = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        checkCsrf();
        $versionName = trim((string)($_POST['version_name'] ?? ''));
        $versionCode = filter_var($_POST['version_code'] ?? null, FILTER_VALIDATE_INT);
        $minimumVersionCode = filter_var($_POST['minimum_version_code'] ?? '1', FILTER_VALIDATE_INT);
        $releaseNotes = trim(strip_tags((string)($_POST['release_notes'] ?? '')));
        if ($versionName === '' || strlen($versionName) > 40 || !preg_match('/^[A-Za-z0-9][A-Za-z0-9._+-]*$/', $versionName)) {
            $err = 'Version name 1.0.0 जैसे format में दें (अधिकतम 40 characters)।';
        } elseif ($versionCode === false || $versionCode < 1 || $minimumVersionCode === false || $minimumVersionCode < 1 || $minimumVersionCode > $versionCode) {
            $err = 'Version code और minimum version code सही positive number होने चाहिए; minimum, latest version से बड़ा नहीं हो सकता।';
        } elseif (strlen($releaseNotes) > 3000) {
            $err = 'Release notes 3000 characters से कम रखें।';
        } else {
            $apk = $_FILES['apk_file'] ?? null;
            $newFilename = '';
            if ($apk && (int)($apk['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
                if ((int)$apk['error'] !== UPLOAD_ERR_OK || (int)$apk['size'] < 1024 || (int)$apk['size'] > 200 * 1024 * 1024) {
                    $err = 'APK upload पूरा नहीं हुआ या file 200 MB से बड़ी है।';
                } else {
                    $tmp = (string)$apk['tmp_name'];
                    $head = file_get_contents($tmp, false, null, 0, 4);
                    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmp);
                    if (strtolower(pathinfo((string)$apk['name'], PATHINFO_EXTENSION)) !== 'apk' || $head !== "PK\x03\x04" || !in_array($mime, ['application/zip', 'application/vnd.android.package-archive', 'application/octet-stream'], true)) {
                        $err = 'सिर्फ valid Android APK file upload करें।';
                    } else {
                        $dir = __DIR__ . '/uploads/app-releases';
                        if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) $err = 'APK folder नहीं बन पाया; hosting folder permissions जाँचें।';
                        else {
                            $newFilename = 'gs-suraha-v' . (int)$versionCode . '-' . date('YmdHis') . '-' . bin2hex(random_bytes(4)) . '.apk';
                            if (!move_uploaded_file($tmp, $dir . '/' . $newFilename)) $err = 'APK server पर save नहीं हो पाई।';
                        }
                    }
                }
            }
            $currentVersionCode = (int)getSetting('app_update_version_code', '1');
            if ($err === '' && (int)$versionCode !== $currentVersionCode && $newFilename === '') {
                $err = 'Version code बदलने पर उसी version का नया APK upload करना ज़रूरी है।';
            }
            if ($err === '') {
                setSetting('app_update_version_name', $versionName);
                setSetting('app_update_version_code', (string)(int)$versionCode);
                setSetting('app_update_min_version_code', (string)(int)$minimumVersionCode);
                setSetting('app_update_release_notes', $releaseNotes);
                setSetting('app_update_enabled', isset($_POST['enabled']) ? '1' : '0');
                if ($newFilename !== '') setSetting('app_update_apk_filename', $newFilename);
                audit('app_release_updated', 'Version ' . $versionName . ' (' . (int)$versionCode . '), APK ' . ($newFilename !== '' ? 'uploaded' : 'unchanged'));
                $msg = 'App release settings save हो गईं। पुराने APK files को हटाया नहीं गया।';
            }
        }
    }
    $versionName = getSetting('app_update_version_name', '1.0.0');
    $versionCode = getSetting('app_update_version_code', '1');
    $minimumVersionCode = getSetting('app_update_min_version_code', '1');
    $releaseNotes = getSetting('app_update_release_notes', '');
    $enabled = getSetting('app_update_enabled', '0') === '1';
    $currentApk = basename(getSetting('app_update_apk_filename', ''));
    ob_start(); ?>
    <style>.app-release-wrap{max-width:850px;margin:20px auto}.app-release-wrap .panel{padding:22px}.app-release-wrap label{display:block;font-weight:700;margin:14px 0 6px}.app-release-wrap input,.app-release-wrap textarea{width:100%;padding:11px;border:1px solid #d5dfd7;border-radius:10px}.app-release-wrap .release-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.app-release-wrap .muted{line-height:1.65}.app-release-wrap .check-row{display:flex;align-items:center;gap:10px;margin:16px 0}.app-release-wrap .check-row input{width:auto}@media(max-width:650px){.app-release-wrap .release-grid{grid-template-columns:1fr}}</style>
    <div class="app-release-wrap"><div class="page-title"><div><div class="eyebrow">SUPER ADMIN</div><h1>📱 Android App Release</h1><p>APK version publish/update करें। पुराने member और payment data को नहीं छुआ जाता।</p></div><a class="btn" href="?route=control-center">← Control Center</a></div>
    <?php if ($msg !== ''): ?><div class="alert success">✅ <?=h($msg)?></div><?php endif; ?>
    <?php if ($err !== ''): ?><div class="alert danger">⚠️ <?=h($err)?></div><?php endif; ?>
    <div class="panel"><h2>Latest app release</h2><p class="muted">Current setting: <b><?=h($versionName)?></b> · version code <b><?=h($versionCode)?></b> · <?= $enabled ? 'Update prompt ON' : 'Update prompt OFF' ?></p><p class="muted">Current APK file: <?= $currentApk !== '' ? h($currentApk) : 'अभी कोई APK upload नहीं है' ?></p>
    <form method="post" enctype="multipart/form-data"><input type="hidden" name="csrf" value="<?=h(csrf())?>">
      <div class="release-grid"><div><label>Version name</label><input name="version_name" value="<?=h($versionName)?>" maxlength="40" placeholder="1.0.1" required></div><div><label>Version code (हर release पर बढ़ाएँ)</label><input type="number" name="version_code" min="1" value="<?=h($versionCode)?>" required></div></div>
      <label>Minimum supported version code (optional enforcement)</label><input type="number" name="minimum_version_code" min="1" value="<?=h($minimumVersionCode)?>" required>
      <label>नया APK upload करें (200 MB तक; signing key/package वही होना चाहिए)</label><input type="file" name="apk_file" accept=".apk,application/vnd.android.package-archive">
      <label>Release notes</label><textarea name="release_notes" rows="4" maxlength="3000" placeholder="इस update में क्या नया है?"><?=h($releaseNotes)?></textarea>
      <label class="check-row"><input type="checkbox" name="enabled" value="1" <?=$enabled?'checked':''?>> APK upload हो और release तैयार हो तो app खोलने पर update prompt दिखाएँ</label>
      <button class="btn primary" type="submit">💾 Release settings save करें</button>
    </form></div>
    <div class="panel"><h2>App logo और launcher icon</h2><p class="muted">App के andar dikhne wala logo तुरंत बदलने के लिए Control Center → Branding में website का header logo बदलें। Android home-screen launcher icon APK में bundled होता है; नया icon लगाने के लिए updated icon के साथ APK rebuild करके ऊपर upload करें। Android install confirmation user को ही करनी होती है।</p><a class="btn" href="?route=control-center&tab=branding">🖼️ Website logo settings खोलें</a></div></div>
    <?php $content = ob_get_clean(); layout('Android App Release', $content); exit;
}

'''

README = '''# GS Suraha website patch\n\nThis patch updates only `index.php` and `assets/style.css` from the supplied `GS_SURAHA_DESKTOP_PAYMENT_FIX.zip`. It adds a Super Admin-only Android release manager, a public read-only JSON version/branding endpoint, an APK download route, and changes Android UPI intent construction so it does not pin the system to Google Pay. The live site header logo (managed in Control Center → Branding) is returned as the app's dynamic in-app logo. Fixed header/footer behavior is applied only inside the Android app's WebView; this patch does not change the website's normal browser layout.\n\n## Deployment\n\n1. Back up the existing website files and database using the hosting provider's normal backup process.\n2. Upload/replace only `index.php` and `assets/style.css` from this patch. Do **not** replace or delete `data/gs_suraha.sqlite`, `uploads/`, or any existing member/payment records.\n3. Sign in with the existing Super Admin account and open `?route=app-release-admin`. Upload an APK, increment its version code, add release notes, and enable the update prompt.\n4. For an in-app logo change, use Control Center → Branding. For a home-screen launcher icon change, rebuild the APK with the new bundled icon, then upload that APK here.\n5. The app reads `?route=app-update-check`; this endpoint is public and exposes only release version, notes, APK URL, and the public header logo URL.\n\nThe upload directory `uploads/app-releases/` is created when the first APK is saved. Ensure the host permits PHP uploads large enough for the APK and has write permission under `uploads/`. Keep the Android application package identifier and signing credential the same for every upgrade; otherwise Android will reject the update as a different app.\n'''

OUT.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(ZIP_PATH) as zf:
    for name in ("index.php", "assets/style.css", "README_CODE_PATCH_ONLY.txt"):
        zf.extract(name, OUT)
php_path = OUT / "index.php"
source = php_path.read_text()
if "if ($route === 'app-update-check')" not in source:
    insertion = "// Public app download page. Works without login so the WhatsApp welcome link is usable by new members."
    if source.count(insertion) != 1:
        raise SystemExit("Expected unique public-download insertion point was not found")
    source = source.replace(insertion, ROUTES + insertion, 1)
old = "package=com.google.android.apps.nbu.paisa.user;"
if old in source:
    source = source.replace(old, "", 1)
if "GS Suraha Android App" not in source:
    marker = '<a class="settings-hub-card" href="?route=control-center&tab=branding"><span class="settings-hub-icon">🖼️</span><span><b>Logo & Branding</b><small>Logo, favicon और banner</small></span></a>'
    if source.count(marker) != 1:
        raise SystemExit("Expected unique Control Center branding card was not found")
    card = marker + '<a class="settings-hub-card" href="?route=app-release-admin"><span class="settings-hub-icon">📱</span><span><b>Android App Release</b><small>APK, version और update prompt</small></span></a>'
    source = source.replace(marker, card, 1)
php_path.write_text(source)
(OUT / "README_CODE_PATCH_ONLY.txt").write_text(README)
print(f"Prepared {php_path} ({php_path.stat().st_size} bytes)")
print(f"UPI package pin removed: {old not in source}")
print("Original live database and uploads were not copied, changed, or deleted.")
