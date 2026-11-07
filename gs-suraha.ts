export const SITE_URL = "https://gssuraha.byethost7.com/";
const RELEASE_URL = `${SITE_URL}?route=app-update-check`;

export type ReleaseInfo = {
  enabled: boolean;
  versionName: string;
  versionCode: number;
  minimumVersionCode: number;
  apkUrl: string;
  releaseNotes: string;
  logoUrl: string;
};

export async function getReleaseInfo(): Promise<ReleaseInfo> {
  const response = await fetch(RELEASE_URL, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Release metadata returned HTTP ${response.status}`);
  const raw: unknown = await response.json();
  if (!raw || typeof raw !== "object") throw new Error("Invalid release metadata");
  const value = raw as Record<string, unknown>;
  const versionCode = Number(value.versionCode);
  const minimumVersionCode = Number(value.minimumVersionCode ?? 1);
  const apkUrl = typeof value.apkUrl === "string" ? value.apkUrl : "";
  const logoUrl = typeof value.logoUrl === "string" ? value.logoUrl : "";
  return {
    enabled: value.enabled === true || value.enabled === 1 || value.enabled === "1",
    versionName: typeof value.versionName === "string" ? value.versionName : "",
    versionCode: Number.isSafeInteger(versionCode) && versionCode > 0 ? versionCode : 0,
    minimumVersionCode: Number.isSafeInteger(minimumVersionCode) && minimumVersionCode > 0 ? minimumVersionCode : 1,
    apkUrl: resolveSiteUrl(apkUrl),
    releaseNotes: typeof value.releaseNotes === "string" ? value.releaseNotes : "",
    logoUrl: resolveSiteUrl(logoUrl),
  };
}

function resolveSiteUrl(value: string): string {
  if (!value) return "";
  try {
    const parsed = new URL(value, SITE_URL);
    if (parsed.protocol !== "https:" || parsed.hostname.toLowerCase() !== "gssuraha.byethost7.com") return "";
    return parsed.toString();
  } catch {
    return "";
  }
}
