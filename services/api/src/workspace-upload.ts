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

import { createReadStream, createWriteStream, copyFileSync } from "node:fs";
import { access, appendFile, copyFile, lstat, mkdir, mkdtemp, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import type { IncomingMessage } from "node:http";
import { tmpdir } from "node:os";
import { basename, dirname, extname, join, relative, resolve, sep } from "node:path";
import { finished } from "node:stream/promises";

import { resolveWorkspaceFile } from "@sciencediscovery/workspace";
import { sha256, sha256File } from "@sciencediscovery/cas";
import type { WorkspaceFile } from "@sciencediscovery/schema";

export type WorkspaceConflictPolicy = "reject" | "overwrite" | "rename";

/** Per-file multipart upload default: 1 GiB. 0 = unlimited. */
export const DEFAULT_WORKSPACE_UPLOAD_MAX_FILE_BYTES = 1_073_741_824;
/** Multipart request body default: 10 GiB, aligned with workspace total. 0 = unlimited. */
export const DEFAULT_WORKSPACE_UPLOAD_MAX_REQUEST_BYTES = 10_737_418_240;
/** Align with runner default workspace quota: 10 GiB. 0 = unlimited. */
export const DEFAULT_WORKSPACE_MAX_BYTES = 10_737_418_240;
/**
 * Multipart parts smaller than this stay in memory; larger ones are spooled
 * to a temporary file so a single large upload never buffers its whole body
 * or a whole file part in RAM (F-25).
 */
export const MULTIPART_IN_MEMORY_PART_BYTES = 8 * 1_024 * 1_024;

export interface WorkspaceUploadLimits {
  maxFileBytes: number;
  maxRequestBytes: number;
  maxWorkspaceBytes: number;
}

export interface MultipartUploadPart {
  /** In-memory content for parts under {@link MULTIPART_IN_MEMORY_PART_BYTES}. */
  bytes: Buffer;
  fieldName: string;
  filename: string;
  /** Absolute path of the spooled file when the part exceeded the memory ceiling. */
  spoolPath?: string;
}

export interface WorkspaceUploadItemResult {
  error?: string;
  hash?: string;
  originalName: string;
  path?: string;
  /** Byte size of the uploaded content; absent on failed entries. */
  size?: number;
  status: "created" | "overwritten" | "renamed" | "failed";
}

export interface WorkspaceUploadResult {
  errors: Array<{ error: string; name: string }>;
  files: WorkspaceFile[];
  uploaded: WorkspaceUploadItemResult[];
}

export function parseConflictPolicy(value: string | null | undefined): WorkspaceConflictPolicy {
  const normalized = value?.trim().toLowerCase();
  if (!normalized || normalized === "rename") return "rename";
  if (normalized === "overwrite" || normalized === "reject") return normalized;
  throw new Error("conflict must be one of rename, overwrite, or reject");
}

export function sanitizeUploadFilename(filename: string): string {
  const normalized = filename.replaceAll("\\", "/").trim();
  if (!normalized) {
    throw Object.assign(new Error("Upload filename is missing or invalid"), { code: "INVALID_UPLOAD_PATH" });
  }
  if (normalized.includes("\0")) {
    throw Object.assign(new Error("Upload filename contains a NUL byte"), { code: "INVALID_UPLOAD_PATH" });
  }
  // Reject traversal / absolute / nested paths instead of silently taking basename.
  // Accept only a plain single-segment basename (WSP-003).
  const absoluteOrDrive =
    normalized.startsWith("/")
    || /^[a-zA-Z]:(\/|$)/.test(normalized)
    || normalized.startsWith("//");
  const hasSeparator = normalized.includes("/");
  const segments = normalized.split("/").filter((segment) => segment.length > 0);
  const hasTraversal = segments.some((segment) => segment === "." || segment === "..");
  if (absoluteOrDrive || hasSeparator || hasTraversal || normalized === "." || normalized === "..") {
    throw Object.assign(
      new Error("Upload filename must be a plain basename without path separators or traversal"),
      { code: "INVALID_UPLOAD_PATH" },
    );
  }
  const base = basename(normalized);
  if (!base || base === "." || base === "..") {
    throw Object.assign(new Error("Upload filename is missing or invalid"), { code: "INVALID_UPLOAD_PATH" });
  }
  return base;
}

/**
 * Parse a multipart/form-data upload with a hard memory ceiling: the request
 * body is streamed to a temporary file (never fully buffered), then scanned in
 * bounded chunks; file parts above {@link MULTIPART_IN_MEMORY_PART_BYTES} are
 * spooled to their own temporary file instead of being held in memory. Only
 * small parts and headers stay in RAM, so a single large upload cannot exhaust
 * the process heap (F-25). Call {@link disposeMultipartUploads} on the result
 * to remove the spooled files once the caller has consumed the parts.
 */
export async function readMultipartUploads(
  request: IncomingMessage,
  maxRequestBytes: number,
): Promise<MultipartUploadPart[]> {
  const contentType = request.headers["content-type"] ?? "";
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
  const boundary = boundaryMatch?.[1] ?? boundaryMatch?.[2];
  if (!boundary || boundary.length > 200) {
    throw Object.assign(new Error("Workspace upload must be multipart/form-data with a valid boundary"), {
      code: "UNSUPPORTED_MEDIA_TYPE",
    });
  }

  const spoolRoot = await mkdtemp(join(tmpdir(), "sciencediscovery-upload-"));
  const bodyPath = join(spoolRoot, "body.bin");
  let totalBytes = 0;
  const writer = createWriteStream(bodyPath, { mode: 0o600 });
  try {
    for await (const chunk of request) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buffer.length;
      // maxRequestBytes === 0 means unlimited (same as per-file / workspace quotas)
      if (maxRequestBytes > 0 && totalBytes > maxRequestBytes) {
        throw Object.assign(new Error(`Workspace upload exceeds the ${maxRequestBytes} byte limit`), {
          code: "PAYLOAD_TOO_LARGE",
        });
      }
      if (!writer.write(buffer)) await new Promise((resolveDrain) => writer.once("drain", resolveDrain));
    }
    writer.end();
    await finished(writer);
  } catch (error) {
    writer.destroy();
    await rm(spoolRoot, { force: true, recursive: true });
    throw error;
  }

  try {
    return await parseMultipartFile(bodyPath, boundary, spoolRoot);
  } finally {
    await rm(bodyPath, { force: true });
  }
}

/** Remove the temporary spool files a parsed upload left behind. */
export async function disposeMultipartUploads(parts: MultipartUploadPart[]): Promise<void> {
  const directories = new Set<string>();
  for (const part of parts) {
    if (part.spoolPath) {
      directories.add(dirname(part.spoolPath));
      await rm(part.spoolPath, { force: true });
    }
  }
  for (const directory of directories) {
    await rm(directory, { force: true, recursive: true });
  }
}

async function parseMultipartFile(bodyPath: string, boundary: string, spoolRoot: string): Promise<MultipartUploadPart[]> {
  const delimiter = Buffer.from(`--${boundary}`);
  const nextDelimiter = Buffer.from(`\r\n--${boundary}`);
  const parts: MultipartUploadPart[] = [];

  /** Accumulator for one file part: memory up to the ceiling, then a spool file. */
  class PartAccumulator {
    readonly chunks: Buffer[] = [];
    size = 0;
    spoolPath?: string;
    constructor(private readonly index: number) {}

    async append(content: Buffer): Promise<void> {
      this.size += content.length;
      if (!this.spoolPath && this.size <= MULTIPART_IN_MEMORY_PART_BYTES) {
        this.chunks.push(content);
        return;
      }
      if (!this.spoolPath) {
        this.spoolPath = join(spoolRoot, `part-${this.index}.bin`);
        await writeFile(this.spoolPath, Buffer.concat(this.chunks), { mode: 0o600 });
        this.chunks.length = 0;
      }
      await appendFile(this.spoolPath, content);
    }

    toPart(fieldName: string, filename: string): MultipartUploadPart {
      if (this.spoolPath) return { bytes: Buffer.alloc(0), fieldName, filename, spoolPath: this.spoolPath };
      return { bytes: Buffer.concat(this.chunks), fieldName, filename };
    }
  }

  // Rolling window that keeps the tail long enough to detect a boundary that
  // straddles two reads. 256 KiB reads bound per-iteration memory; the window
  // is trimmed aggressively so a huge part body never accumulates in RAM.
  let window = Buffer.alloc(0);
  let inFilePart: { accumulator: PartAccumulator; fieldName: string; filename: string } | undefined;
  let foundClosingBoundary = false;

  const processWindow = async (): Promise<void> => {
    for (;;) {
      if (inFilePart) {
        // Consume part body bytes up to the next `\r\n--boundary`.
        const contentEnd = window.indexOf(nextDelimiter);
        if (contentEnd < 0) {
          // No delimiter yet: forward everything except the boundary's prefix
          // so a split delimiter is still detected on the next chunk.
          const keep = Math.max(0, nextDelimiter.length - 1);
          const forward = window.length - keep;
          if (forward > 0) {
            await inFilePart.accumulator.append(window.subarray(0, forward));
            window = window.subarray(forward);
          }
          return;
        }
        await inFilePart.accumulator.append(window.subarray(0, contentEnd));
        parts.push(inFilePart.accumulator.toPart(inFilePart.fieldName, inFilePart.filename));
        inFilePart = undefined;
        window = window.subarray(contentEnd + 2); // swallow the leading `\r\n`
        continue;
      }
      const startAt = window.indexOf(delimiter);
      if (startAt < 0) {
        // No boundary anywhere: keep a tail that could still form one.
        const keep = Math.max(0, delimiter.length + 2);
        window = window.length > keep ? window.subarray(window.length - keep) : window;
        return;
      }
      // Skip the preamble/bytes before this boundary.
      window = window.subarray(startAt);
      if (window.length < delimiter.length + 2) return; // need the `--` / `\r\n` verdict
      const after = window.subarray(delimiter.length, delimiter.length + 2);
      if (after.equals(Buffer.from("--"))) {
        foundClosingBoundary = true;
        return;
      }
      if (!after.equals(Buffer.from("\r\n"))) throw new Error("Workspace upload multipart body is malformed");
      const headerStart = delimiter.length + 2;
      const headerEnd = window.indexOf(Buffer.from("\r\n\r\n"), headerStart);
      if (headerEnd < 0) {
        // Headers not complete yet; keep enough to finish them.
        window = window.subarray(Math.max(0, window.length - 4_096));
        return;
      }
      const headers = window.subarray(headerStart, headerEnd).toString("utf8");
      const contentDisposition = headers.split("\r\n").find((line) => /^content-disposition:/i.test(line));
      const fieldName = contentDisposition?.match(/\bname="([^"]+)"/i)?.[1] ?? "";
      const rawFilename = contentDisposition?.match(/\bfilename\*?=(?:UTF-8''|")?([^";]+)"?/i)?.[1];
      const contentStart = headerEnd + 4;
      window = window.subarray(contentStart);
      if ((fieldName === "file" || fieldName === "files") && rawFilename) {
        inFilePart = { accumulator: new PartAccumulator(parts.length), fieldName, filename: decodeUploadFilename(rawFilename) };
      }
    }
  };

  const reader = createReadStream(bodyPath, { highWaterMark: 256 * 1_024 });
  for await (const chunk of reader) {
    window = window.length ? Buffer.concat([window, chunk]) : chunk;
    await processWindow();
    if (foundClosingBoundary) break;
  }
  if (inFilePart) throw new Error("Workspace upload multipart body has no closing boundary");
  if (!foundClosingBoundary && window.length >= 2) {
    // Body ended without an explicit closing boundary — a malformed request.
    if (parts.length) throw new Error("Workspace upload multipart body has no closing boundary");
  }
  if (!parts.length) throw new Error("Workspace upload must contain at least one file field");
  return parts;
}

function decodeUploadFilename(raw: string): string {
  try {
    return decodeURIComponent(raw.trim());
  } catch {
    return raw.trim();
  }
}

export async function measureWorkspaceBytes(workspaceRoot: string): Promise<number> {
  let total = 0;
  async function visit(directory: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = resolve(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        await visit(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const metadata = await stat(fullPath);
      total += metadata.size;
    }
  }
  await visit(workspaceRoot);
  return total;
}

/** Lexical containment plus per-segment symlink rejection for upload targets. */
async function assertSafeWorkspaceTarget(workspaceRoot: string, relativePath: string): Promise<string> {
  const target = resolveWorkspaceFile(workspaceRoot, relativePath);
  const root = resolve(workspaceRoot);
  let current = root;
  const segments = relative(root, target).split(sep).filter(Boolean);
  for (let index = 0; index < segments.length; index += 1) {
    current = resolve(current, segments[index]!);
    let metadata;
    try {
      metadata = await lstat(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") break;
      throw error;
    }
    if (metadata.isSymbolicLink()) {
      throw new Error(`Path escapes the workspace through a symbolic link: ${relativePath}`);
    }
    if (index < segments.length - 1 && !metadata.isDirectory()) {
      throw new Error(`Upload path parent is not a directory: ${relativePath}`);
    }
    if (index === segments.length - 1 && !metadata.isFile() && !metadata.isDirectory()) {
      throw new Error(`Refusing to write special device path: ${relativePath}`);
    }
  }
  return target;
}

export async function allocateUploadPath(
  workspaceRoot: string,
  filename: string,
  conflict: WorkspaceConflictPolicy,
): Promise<{ path: string; status: "created" | "overwritten" | "renamed" }> {
  const safeName = sanitizeUploadFilename(filename);
  const primary = await assertSafeWorkspaceTarget(workspaceRoot, safeName);
  try {
    await access(primary);
  } catch {
    return { path: safeName, status: "created" };
  }
  if (conflict === "reject") {
    throw Object.assign(new Error(`File already exists: ${safeName}`), { code: "CONFLICT" });
  }
  if (conflict === "overwrite") {
    return { path: safeName, status: "overwritten" };
  }
  const extension = extname(safeName);
  const stem = extension ? safeName.slice(0, -extension.length) : safeName;
  for (let index = 1; index < 10_000; index += 1) {
    const candidateName = `${stem}-${index}${extension}`;
    const candidate = await assertSafeWorkspaceTarget(workspaceRoot, candidateName);
    try {
      await access(candidate);
    } catch {
      return { path: candidateName, status: "renamed" };
    }
  }
  throw new Error(`Could not allocate a unique name for ${safeName}`);
}

export async function writeWorkspaceUpload(options: {
  bytes: Buffer;
  conflict: WorkspaceConflictPolicy;
  filename: string;
  limits: WorkspaceUploadLimits;
  workspaceRoot: string;
  workspaceBytes?: number;
  /** Spooled part content; when set, `bytes` is ignored and the file is copied. */
  spoolPath?: string;
}): Promise<WorkspaceUploadItemResult & { absolutePath: string; bytesWritten: number }> {
  const originalName = sanitizeUploadFilename(options.filename);
  const partSize = options.spoolPath ? (await stat(options.spoolPath)).size : options.bytes.length;
  if (options.limits.maxFileBytes > 0 && partSize > options.limits.maxFileBytes) {
    throw Object.assign(
      new Error(`File exceeds the ${options.limits.maxFileBytes} byte upload limit`),
      { code: "PAYLOAD_TOO_LARGE" },
    );
  }
  const allocation = await allocateUploadPath(options.workspaceRoot, originalName, options.conflict);
  const target = await assertSafeWorkspaceTarget(options.workspaceRoot, allocation.path);
  const currentBytes = options.workspaceBytes ?? await measureWorkspaceBytes(options.workspaceRoot);
  let replacedBytes = 0;
  if (allocation.status === "overwritten") {
    try {
      replacedBytes = (await stat(target)).size;
    } catch {
      replacedBytes = 0;
    }
  }
  if (
    options.limits.maxWorkspaceBytes > 0
    && currentBytes - replacedBytes + partSize > options.limits.maxWorkspaceBytes
  ) {
    throw Object.assign(
      new Error(`Upload would exceed the ${options.limits.maxWorkspaceBytes} byte workspace quota`),
      { code: "QUOTA_EXCEEDED" },
    );
  }
  await mkdir(dirname(target), { recursive: true });
  const staging = `${target}.uploading-${process.pid}-${Date.now()}`;
  try {
    if (options.spoolPath) {
      await copyFile(options.spoolPath, staging);
    } else {
      await writeFile(staging, options.bytes);
    }
    const staged = await lstat(staging);
    if (!staged.isFile()) throw new Error("Upload staging path is not a regular file");
    await rename(staging, target);
  } catch (error) {
    await rm(staging, { force: true }).catch(() => undefined);
    throw error;
  }
  return {
    absolutePath: target,
    bytesWritten: partSize,
    hash: options.spoolPath ? await sha256File(options.spoolPath) : sha256(options.bytes),
    originalName,
    path: allocation.path,
    status: allocation.status,
  };
}

export async function uploadWorkspaceParts(options: {
  conflict: WorkspaceConflictPolicy;
  limits: WorkspaceUploadLimits;
  listFiles: () => Promise<WorkspaceFile[]>;
  parts: MultipartUploadPart[];
  registerArtifact?: (path: string) => Promise<void>;
  workspaceRoot: string;
}): Promise<WorkspaceUploadResult> {
  const uploaded: WorkspaceUploadItemResult[] = [];
  const errors: Array<{ error: string; name: string }> = [];
  let workspaceBytes = await measureWorkspaceBytes(options.workspaceRoot);
  for (const part of options.parts) {
    try {
      const partSize = part.spoolPath ? (await stat(part.spoolPath)).size : part.bytes.length;
      if (options.limits.maxFileBytes > 0 && partSize > options.limits.maxFileBytes) {
        throw Object.assign(
          new Error(`File exceeds the ${options.limits.maxFileBytes} byte upload limit`),
          { code: "PAYLOAD_TOO_LARGE" },
        );
      }
      const written = await writeWorkspaceUpload({
        bytes: part.bytes,
        conflict: options.conflict,
        filename: part.filename,
        limits: options.limits,
        spoolPath: part.spoolPath,
        workspaceBytes,
        workspaceRoot: options.workspaceRoot,
      });
      workspaceBytes += written.bytesWritten;
      if (written.status === "overwritten") {
        // replaced size already subtracted inside writeWorkspaceUpload quota check via replacedBytes,
        // but workspaceBytes tracker here only adds; remeasure cheaply for correctness after overwrite.
        workspaceBytes = await measureWorkspaceBytes(options.workspaceRoot);
      }
      if (written.path && options.registerArtifact) await options.registerArtifact(written.path);
      uploaded.push({
        hash: written.hash,
        originalName: written.originalName,
        path: written.path,
        size: written.bytesWritten,
        status: written.status,
      });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "INVALID_UPLOAD_PATH") throw error;
      const message = error instanceof Error ? error.message : "Upload failed";
      const name = (() => {
        try {
          return sanitizeUploadFilename(part.filename);
        } catch {
          return part.filename || "unnamed";
        }
      })();
      uploaded.push({ error: message, originalName: name, status: "failed" });
      errors.push({ error: message, name });
    }
  }
  return {
    errors,
    files: await options.listFiles(),
    uploaded,
  };
}

export async function readFileSha256(path: string): Promise<string> {
  return await sha256File(path);
}

/** Map an upload filename to a media type by extension, for the memory graph's
 * SourceFile node. Returns ``undefined`` for unknown extensions so the graph
 * stores an absent (not a wrong) media_type. Case-insensitive on the suffix. */
export function inferMediaType(filename: string): string | undefined {
  const ext = extname(filename).toLowerCase();
  switch (ext) {
    case ".csv":
      return "text/csv";
    case ".tsv":
      return "text/tab-separated-values";
    case ".json":
      return "application/json";
    case ".jsonl":
      return "application/jsonl+json";
    case ".png":
      return "image/png";
    case ".jpg":
    case ".jpeg":
      return "image/jpeg";
    case ".gif":
      return "image/gif";
    case ".svg":
      return "image/svg+xml";
    case ".pdf":
      return "application/pdf";
    case ".md":
      return "text/markdown";
    case ".txt":
      return "text/plain";
    case ".parquet":
      return "application/vnd.apache.parquet";
    case ".xlsx":
      return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    case ".h5":
    case ".hdf5":
      return "application/x-hdf5";
    // Common research formats beyond the basics. None of these are PDFs —
    // what matters for the graph's cite gates is only that a known non-PDF
    // type is recorded, so the claim route (cites_source_file_aliases) can
    // proceed; the specific string is informational.
    case ".npy":
      return "application/x-npy";
    case ".npz":
      return "application/x-npz";
    case ".pkl":
    case ".pickle":
      return "application/x-pickle";
    case ".fasta":
    case ".fa":
    case ".fna":
    case ".faa":
      return "text/x-fasta";
    case ".fastq":
    case ".fq":
      return "text/x-fastq";
    case ".vcf":
      return "text/x-vcf";
    case ".hypo":
      return "application/octet-stream";
    case ".zip":
      return "application/zip";
    case ".tar":
      return "application/x-tar";
    case ".gz":
    case ".tgz":
      return "application/gzip";
    case ".xml":
      return "application/xml";
    case ".yaml":
    case ".yml":
      return "application/yaml";
    case ".toml":
      return "application/toml";
    case ".rds":
      return "application/x-rds";
    case ".dta":
      return "application/x-stata";
    case ".sav":
      return "application/x-spss-sav";
    case ".mat":
      return "application/x-matlab-data";
    case ".tif":
    case ".tiff":
      return "image/tiff";
    case ".bmp":
      return "image/bmp";
    case ".webp":
      return "image/webp";
    default:
      return undefined;
  }
}
