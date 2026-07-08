const ACTIVE_CONTENT_EXT_RE = /\.(?:html?|xhtml|svg|js|mjs|cjs|jsx|ts|tsx|vbs|wsf|hta|bat|cmd|com|exe|msi|ps1|sh)$/iu;

export function sanitizeDownloadFileName(fileName: string): string {
  const baseName = fileName.trim().split(/[/\\]+/u).pop() ?? "";
  const cleaned = baseName
    .replace(/[^A-Za-z0-9._-]+/gu, "_")
    .replace(/_+/gu, "_")
    .replace(/^\.+/u, "")
    .slice(0, 120);
  const safeName = cleaned || "download.bin";
  return ACTIVE_CONTENT_EXT_RE.test(safeName) ? `${safeName}.download` : safeName;
}

export function safeDownload(blob: Blob, fileName: string): void {
  const safeName = sanitizeDownloadFileName(fileName);
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = safeName;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}
