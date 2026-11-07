# GS Suraha Android app and update flow

## Latest size reduction

The Android shell is now a single Expo entry point (`App.tsx` + `index.js`) with only the WebView, updater, UPI handoff, splash, and application modules retained. Expo Router, NativeWind, Reanimated, Safe Area Context, TRPC/React Query, OAuth callback UI, starter demo routes, and unused image assets were removed from the mobile runtime. Android remains `arm64-v8a` only, release minification/resource shrinking remains enabled, and launcher/splash images were reduced to 512px optimized PNGs. The exported Android JavaScript bundle validates at approximately 1.5 MB. The final signed APK must still be built with EAS to measure the exact compressed APK; this source does not claim a 5 MB APK until that measurement is available.

The app-only injected CSS pins the public front-page contact row and navigation row together at the top, dynamically compensating for their measured combined height. The authenticated artwork header and mobile bottom navigation remain pinned as before. These rules apply only inside the app WebView and do not alter the standalone website.

## App behavior

The app opens `https://gssuraha.byethost7.com` in a WebView. The Android app injects fixed-header and fixed-footer styling only into its own WebView; normal browsing on the website is unchanged. Both the authenticated dashboard artwork header and the public front-page contact/navigation header are pinned at the top; the front-page rows are measured dynamically. UPI payment links open an external UPI app. The supplied GS Suraha logo is used in the native launcher/adaptive/splash images, preserving the complete artwork and aspect ratio.

On app launch and foreground return, the app checks the website's public update metadata. If a newer APK is available, it prompts, downloads the file and opens Android's installer. The phone owner must confirm installation and may need to allow installs from this app.

## APK size

The first APK measured 51 MB; after compressed native-library packaging, the user reported the rebuilt APK was 25 MB. This source removes the remaining unused mobile runtime packages and starter routes, retains only `arm64-v8a`, and optimizes native images. Whether the final APK reaches the requested 5 MB remains unverified until EAS completes the signed build; native React Native/WebView runtime size cannot be inferred from the JavaScript bundle alone. [Expo app-size guide](https://docs.expo.dev/distribution/app-size/) · [Expo Android build properties](https://docs.expo.dev/versions/latest/sdk/build-properties/).

## Build and release

On Windows, open Command Prompt in the extracted project root. Sign in with the Expo account that owns `@gunsagark/gssuraha`. This source uses `pnpm-lock.yaml`; do not run `npm install`. If `package-lock.json` exists, delete it. If Git is absent, set `EAS_NO_VCS=1`, then run `eas build --platform android --profile preview`. EAS project ID is `8075fde2-8ea3-4bd1-b265-4049c941cf43`. Current source version is `1.0.4`, Android code `5`, package ID `space.manus.gssuraha.t049028030375259`. Keep the same remote Android keystore created by the first build; never generate a new key for updates. Enter version `1.0.4` and version code `5` when publishing this APK through the site's release page. Android rejects updates signed by a different key.

## Website patch

The separate PHP patch adds a Super Admin release manager, public read-only update metadata/download routes, and removes the Google Pay package pin from UPI intent links. The supplied `assets/style.css` is left as-is; fixed top/bottom behavior is app-only. The ZIP does not contain a database or uploaded data. For deployment, back up hosting files/database and replace only `index.php` and `assets/style.css`; never replace/delete `data/gs_suraha.sqlite` or `uploads/`. After patching, sign in as the existing Super Admin and open `?route=app-release-admin` to upload the APK and turn on update prompts.
