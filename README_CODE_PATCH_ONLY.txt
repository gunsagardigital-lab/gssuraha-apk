# GS Suraha website patch

This patch updates only `index.php` and `assets/style.css` from the supplied `GS_SURAHA_DESKTOP_PAYMENT_FIX.zip`. It adds a Super Admin-only Android release manager, a public read-only JSON version/branding endpoint, an APK download route, and changes Android UPI intent construction so it does not pin the system to Google Pay. The live site header logo (managed in Control Center → Branding) is returned as the app's dynamic in-app logo. Fixed header/footer behavior is applied only inside the Android app's WebView; this patch does not change the website's normal browser layout.

## Deployment

1. Back up the existing website files and database using the hosting provider's normal backup process.
2. Upload/replace only `index.php` and `assets/style.css` from this patch. Do **not** replace or delete `data/gs_suraha.sqlite`, `uploads/`, or any existing member/payment records.
3. Sign in with the existing Super Admin account and open `?route=app-release-admin`. Upload an APK, increment its version code, add release notes, and enable the update prompt.
4. For an in-app logo change, use Control Center → Branding. For a home-screen launcher icon change, rebuild the APK with the new bundled icon, then upload that APK here.
5. The app reads `?route=app-update-check`; this endpoint is public and exposes only release version, notes, APK URL, and the public header logo URL.

The upload directory `uploads/app-releases/` is created when the first APK is saved. Ensure the host permits PHP uploads large enough for the APK and has write permission under `uploads/`. Keep the Android application package identifier and signing credential the same for every upgrade; otherwise Android will reject the update as a different app.
