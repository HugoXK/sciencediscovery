// Copyright (C) 2026-2026 Huawei Technologies Co., Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * Text classification and line pagination for workspace reads.
 *
 * Two rules keep a read bounded before it becomes model input. First, binary
 * content is never inlined — not as a body and not as base64 — so the model
 * gets type and size metadata and picks a non-text path instead. Second, text
 * is served one page at a time, streamed so a multi-gigabyte log costs one
 * page of memory rather than a full buffer.
 *
 * Classification is content-based on purpose: scientific text formats such as
 * PDB, CIF, FASTA, and MOL carry media types that are not `text/*`, and they
 * must stay readable.
 */

import { createReadStream } from "node:fs";
import { open } from "node:fs/promises";
import { extname } from "node:path";

import { DEFAULT_READ_PAGE_MAX_BYTES, DEFAULT_TOOL_OUTPUT_MAX_LINES } from "@sciencediscovery/tools";

/** Bytes inspected when deciding whether content is text. */
const SNIFF_BYTES = 8_192;

const MEDIA_TYPES_BY_EXTENSION: Readonly<Record<string, string>> = {
  ".adoc": "text/plain",
  ".bin": "application/octet-stream",
  ".bz2": "application/x-bzip2",
  ".cif": "chemical/x-cif",
  ".csv": "text/csv",
  ".doc": "application/msword",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".fasta": "chemical/x-fasta",
  ".gif": "image/gif",
  ".gz": "application/gzip",
  ".h5": "application/x-hdf5",
  ".jpeg": "image/jpeg",
  ".jpg": "image/jpeg",
  ".json": "application/json",
  ".log": "text/plain",
  ".md": "text/markdown",
  ".markdown": "text/markdown",
  ".mdx": "text/markdown",
  ".mol": "chemical/x-mdl-molfile",
  ".mrc": "application/octet-stream",
  ".nc": "application/x-netcdf",
  ".npy": "application/x-numpy",
  ".npz": "application/x-numpy",
  ".parquet": "application/vnd.apache.parquet",
  ".pdb": "chemical/x-pdb",
  ".pdf": "application/pdf",
  ".pkl": "application/octet-stream",
  ".png": "image/png",
  ".org": "text/plain",
  ".pt": "application/octet-stream",
  ".qmd": "text/markdown",
  ".py": "text/x-python",
  ".r": "text/x-r",
  ".sdf": "chemical/x-mdl-sdfile",
  ".rst": "text/plain",
  ".tar": "application/x-tar",
  ".tif": "image/tiff",
  ".tiff": "image/tiff",
  ".tsv": "text/tab-separated-values",
  ".txt": "text/plain",
  ".webp": "image/webp",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".xml": "application/xml",
  ".yaml": "application/yaml",
  ".yml": "application/yaml",
  ".zip": "application/zip",
};

export function guessMediaType(path: string): string {
  return MEDIA_TYPES_BY_EXTENSION[extname(path).toLowerCase()] ?? "application/octet-stream";
}

/**
 * Decide from the bytes themselves whether content can enter model input as
 * text. A NUL byte or invalid UTF-8 means binary; a trailing partial code
 * point at the end of the sniff window does not.
 */
export function isBinaryContent(sample: Buffer, partialSample = false): boolean {
  if (sample.length === 0) return false;
  if (sample.includes(0)) return true;
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const backoff = partialSample ? 3 : 0;
  for (let trim = 0; trim <= backoff; trim += 1) {
    try {
      decoder.decode(sample.subarray(0, sample.length - trim));
      return false;
    } catch {
      // Retry without the trailing bytes that may hold a split code point.
    }
  }
  return true;
}

export async function detectBinaryFile(path: string): Promise<boolean> {
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.alloc(SNIFF_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, SNIFF_BYTES, 0);
    return isBinaryContent(buffer.subarray(0, bytesRead), bytesRead === SNIFF_BYTES);
  } finally {
    await handle.close();
  }
}

export interface TextPageOptions {
  limit?: number;
  maxBytes?: number;
  /** 1-based line to start from. */
  offset?: number;
}

export interface TextFilePage {
  bytes: number;
  /** Last 1-based line included; `startLine - 1` when the page is empty. */
  endLine: number;
  hasMore: boolean;
  nextOffset?: number;
  /**
   * True when a single line was wider than the page budget and had to be cut.
   * Line offsets cannot address the remainder, so the caller must tell the
   * model to slice that line with a shell/Python read instead.
   */
  partialLine: boolean;
  startLine: number;
  text: string;
  /** Known only when the read reached end of file. */
  totalLines?: number;
}

/**
 * Read one page of lines, preserving each line's own terminator so a whole
 * file read is byte-identical to the file. The stream is destroyed as soon as
 * the page is full, so paging never depends on total file size.
 */
export async function readTextFilePage(path: string, options: TextPageOptions = {}): Promise<TextFilePage> {
  const startLine = Math.max(1, Math.trunc(options.offset ?? 1));
  const maxLines = Math.max(1, Math.trunc(options.limit ?? DEFAULT_TOOL_OUTPUT_MAX_LINES));
  const maxBytes = Math.max(1, options.maxBytes ?? DEFAULT_READ_PAGE_MAX_BYTES);

  const kept: string[] = [];
  let bytes = 0;
  let lineNumber = 0;
  let hasMore = false;
  let partialLine = false;
  let reachedEnd = true;
  let linePieces: string[] = [];
  let lineBytes = 0;
  let unterminatedLine = false;

  /** Keep only the current page budget, even when a line never ends. */
  const append = (piece: string, endsLine: boolean): boolean => {
    if (kept.length >= maxLines) return false;
    const size = Buffer.byteLength(piece, "utf8");
    const remaining = maxBytes - bytes - lineBytes;
    if (size > remaining) {
      if (kept.length > 0) return false;
      const head = sliceToBytes(piece, remaining);
      if (head) linePieces.push(head);
      lineBytes += Buffer.byteLength(head, "utf8");
      kept.push(linePieces.join(""));
      bytes += lineBytes;
      partialLine = true;
      return false;
    }
    linePieces.push(piece);
    lineBytes += size;
    if (endsLine) {
      kept.push(linePieces.join(""));
      bytes += lineBytes;
      linePieces = [];
      lineBytes = 0;
    }
    return true;
  };

  const stream = createReadStream(path, { encoding: "utf8" });
  try {
    reading: for await (const chunk of stream) {
      const text = chunk as string;
      let cursor = 0;
      while (cursor < text.length) {
        const newline = text.indexOf("\n", cursor);
        const endsLine = newline !== -1;
        const nextCursor = endsLine ? newline + 1 : text.length;
        const piece = text.slice(cursor, nextCursor);
        if (lineNumber + 1 >= startLine && !append(piece, endsLine)) {
          hasMore = true;
          reachedEnd = false;
          break reading;
        }
        unterminatedLine = !endsLine;
        if (endsLine) lineNumber += 1;
        cursor = nextCursor;
      }
    }
  } finally {
    stream.destroy();
  }
  if (reachedEnd && unterminatedLine) {
    lineNumber += 1;
    if (lineNumber >= startLine) {
      kept.push(linePieces.join(""));
      bytes += lineBytes;
    }
  }

  const endLine = startLine + kept.length - 1;
  return {
    bytes,
    endLine,
    hasMore,
    ...(hasMore ? { nextOffset: endLine + 1 } : {}),
    partialLine,
    startLine,
    text: kept.join(""),
    ...(reachedEnd ? { totalLines: lineNumber } : {}),
  };
}

function sliceToBytes(text: string, maxBytes: number): string {
  const picked: string[] = [];
  let bytes = 0;
  for (const character of text) {
    const size = Buffer.byteLength(character, "utf8");
    if (bytes + size > maxBytes) break;
    picked.push(character);
    bytes += size;
  }
  return picked.join("");
}
