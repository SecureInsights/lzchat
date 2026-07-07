export function safeDownload(blob: Blob, fileName: string): void {
  const safeName = fileName.replace(/[^\w .()[\]-]+/gu, "_").slice(0, 120) || "download.bin";
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
