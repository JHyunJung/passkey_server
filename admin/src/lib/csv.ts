/**
 * Client-side CSV export helpers.
 *
 * Server has no /export endpoint — for Phase B we keep the data plane simple
 * by paginating the existing JSON endpoints client-side and serialising rows in
 * the browser. A future enhancement can move this to a server-streamed CSV.
 */

/** RFC 4180-style escaping. */
function escapeCsvCell(value: unknown): string {
  if (value == null) return "";
  const str = String(value);
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Turn an array of plain objects into a CSV string with the given column order.
 *
 * <p>The generic {@code T} intentionally omits an index signature — typed DTOs
 * from {@code types/api.ts} are interfaces without index signatures, and forcing
 * one would leak through the entire type graph. We cast row access internally
 * because columns are validated at compile time via {@code keyof T}.
 */
export function rowsToCsv<T>(
  rows: T[],
  columns: { key: keyof T; header: string }[],
): string {
  const header = columns.map((c) => escapeCsvCell(c.header)).join(",");
  const body = rows
    .map((row) =>
      columns
        .map((c) => escapeCsvCell((row as Record<string, unknown>)[c.key as string]))
        .join(","),
    )
    .join("\n");
  return `${header}\n${body}\n`;
}

/** Trigger a browser download of the CSV string under {@code filename}. */
export function downloadCsv(filename: string, csv: string): void {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
