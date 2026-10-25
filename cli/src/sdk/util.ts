/** Small helpers the SDK and the scripts both want. */

import type { Params } from "./params.js";

/** The fresh noise bound, read from the parameter set. */
export function freshNoiseBoundOf(p: Params): bigint {
  return p.freshNoiseBound;
}

/** Format a byte count the way the CLI and the docs do. */
export function humanBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}

/** sha256, used for the off-chain result digest. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const { createHash } = await import("node:crypto");
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}
