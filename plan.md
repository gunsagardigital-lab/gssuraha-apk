# GS Suraha Android App — Implementation Plan

## Scope and decisions

Build an Android app shell around the existing live GS Suraha site at `https://gssuraha.byethost7.com`. The website remains the primary member/admin interface and source of business data. The app embeds the site in WebView, preserves normal site navigation and login behavior, and launches UPI payment links with Android's external UPI-app handling.

The app injects CSS inside its own WebView to keep both the authenticated dashboard header and the public front-page contact/navigation header at the top, and mobile bottom tabs at the bottom while scrolling. The front-page header rows are measured dynamically. These position changes are app-only: standalone website CSS is not modified. The supplied GS Suraha logo is used for native launcher, adaptive and splash identity without cropping or distorting the original artwork.

The website Super Admin can publish APK version metadata and an APK file. At launch and foreground return, the app compares installed and published versions and offers an update download/install handoff. Android keeps its installation confirmation and unknown-source permission under the phone owner's control. Changing the launcher icon requires a newly built APK.

The user supplied `GS_SURAHA_DESKTOP_PAYMENT_FIX.zip`; its instructions prohibit replacing/deleting the live `data/gs_suraha.sqlite` or `uploads/`. The website patch excludes both. Hosting credentials/access were not provided, so deployment is not performed.

## Design and implementation

Reuse the existing rural-cooperative website identity for the embedded experience. Native update dialogs use green and saffron accents. Do not overlay a duplicate native brand header or bottom tab bar.

Keep the initialized Expo Router / React Native / TypeScript project and its generated Android package ID. The WebView fills the app screen, with app-injected fixed top-header and bottom-tab rules; Android back navigation and external UPI launching remain native. The updater reads public site release metadata, compares numeric version codes, downloads the APK and invokes Android's package installer.

The provided PHP source is patched separately with public read-only release metadata/download routes, a Super Admin-only APK manager, and UPI intents without a Google Pay package pin. Only the specified PHP files are replaced during deployment, never the site's database or uploads.

## APK size target

The user requests an APK below 10 MB; their first EAS APK measured 51 MB and their compressed build measured 25 MB. Remove unused native packages and starter demo routes, optimize supplied PNG assets, enable Android release minification/resource shrinking, JavaScript bundle compression and compressed native-library packaging. The user explicitly approved a 64-bit-only (`arm64-v8a`) APK to reduce size; older 32-bit ARM devices will not support it. Do not promise the size target until the next native APK is built and measured.

The screenshot's blank band above the authenticated dashboard header was caused by the site's more-specific `.topbar-with-artwork { position: relative !important; }` rule overriding the generic WebView injection while the added 64px content offset remained. The app injection now targets it with higher specificity. It also pins both public front-page header rows and dynamically preserves their combined height; standalone website CSS remains unchanged.

Current source release version: `1.0.4`, Android version code `5`; application ID remains `space.manus.gssuraha.t049028030375259`. Future builds must preserve package ID and the EAS remote signing credential and increment version code.

## Project structure

- `app/(tabs)/index.tsx`: main WebView screen, app-only fixed-bar CSS injection, UPI and APK update handling.
- `app/(tabs)/_layout.tsx`: hides the redundant Expo tab bar.
- `lib/gs-suraha.ts`: website release metadata and logo API types.
- `assets/images/`: provided logo used for launcher, adaptive, splash and favicon assets.
- `app.config.ts`: app branding, Android package/version and native release-size options.
- `website-patch/`: separate PHP patch and deployment notes; includes no live database/uploads.
