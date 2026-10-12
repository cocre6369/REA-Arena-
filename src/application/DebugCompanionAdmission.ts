import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { open, readdir, stat } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import type { FileHandle } from "node:fs/promises";

import { err, ok, type Result } from "../domain/result.js";
import type {
  BinaryArchitecture,
  MachODebugCompanion,
} from "../domain/binaryTargetTypes.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import {
  debugCompanionMatches,
  readMachoUuidEntries,
  type MachOUuidEntry,
} from "../domain/machoDebugCompanion.js";

/** Bound on the bytes read to walk Mach-O headers and load commands. */
const HEADER_READ_LIMIT = 64 * 1024;

const DSYM_DWARF_DIRECTORY = join("Contents", "Resources", "DWARF");

/**
 * Mach-O cputypes for the provider-neutral CPU families REA admits, including
 * the 64-bit flag the ABI sets on x86_64 and arm64. MIPS has no Mach-O
 * cputype; a companion can never match it.
 */
const CPU_TYPES: Readonly<Record<BinaryArchitecture, readonly number[]>> = {
  x86: [0x00000007],
  x86_64: [0x01000007],
  arm: [0x0000000c],
  arm64: [0x0100000c],
  mips: [],
};

/** Admitted identity of a caller-selected dSYM companion. */
export type DebugCompanionAdmission = Result<
  MachODebugCompanion,
  DebugCompanionRejection
>;

/** Why a caller-selected debug companion was refused, in caller-facing words. */
export interface DebugCompanionRejection {
  readonly reason: string;
}

const throwIfCancelled = (signal: AbortSignal | undefined): void => {
  if (signal?.aborted === true)
    throw new AnalysisCancelledError("resolve_binary_target");
};

const readUuidWindow = async (
  handle: FileHandle,
  offset: number,
  length: number,
): Promise<Result<Buffer, string>> => {
  const window = Buffer.alloc(Math.min(length, HEADER_READ_LIMIT));
  const observed = await handle.read(window, 0, window.length, offset);
  return ok(window.subarray(0, observed.bytesRead));
};

/**
 * Read every LC_UUID of a Mach-O file with its declaring cputype: a thin
 * image from its start, or each slice of a universal container from its table.
 */
export const readMachoFileUuidEntries = async (
  handle: FileHandle,
  fileSize: number,
): Promise<Result<MachOUuidEntry[], string>> => {
  const prefix = await readUuidWindow(handle, 0, fileSize);
  if (!prefix.ok) return prefix;
  const magic = prefix.value.length >= 4 ? prefix.value.readUInt32BE(0) : 0;
  if (magic !== 0xcafebabe && magic !== 0xcafebabf)
    return readMachoUuidEntries(prefix.value);
  const wide = magic === 0xcafebabf;
  if (prefix.value.length < 8)
    return err("the universal Mach-O container header is truncated");
  const count = prefix.value.readUInt32BE(4);
  const entrySize = wide ? 32 : 20;
  if (count > 128 || 8 + count * entrySize > prefix.value.length)
    return err("the universal Mach-O container table is truncated");
  const entries: MachOUuidEntry[] = [];
  for (let index = 0; index < count; index += 1) {
    const entry = 8 + index * entrySize;
    const cpuType = prefix.value.readInt32BE(entry);
    const sliceOffset = wide
      ? Number(prefix.value.readBigUInt64BE(entry + 8))
      : prefix.value.readUInt32BE(entry + 8);
    const sliceSize = wide
      ? Number(prefix.value.readBigUInt64BE(entry + 16))
      : prefix.value.readUInt32BE(entry + 12);
    if (sliceOffset > fileSize || sliceSize > fileSize - sliceOffset)
      return err("a universal Mach-O slice is out of file bounds");
    const slice = await readUuidWindow(handle, sliceOffset, sliceSize);
    if (!slice.ok) return slice;
    const read = readMachoUuidEntries(slice.value);
    if (!read.ok) return read;
    for (const item of read.value) entries.push({ cpuType, uuid: item.uuid });
  }
  return ok(entries);
};

const sameFile = (initial: Stats, observed: Stats): boolean =>
  initial.dev === observed.dev &&
  initial.ino === observed.ino &&
  initial.size === observed.size &&
  initial.mtimeMs === observed.mtimeMs;

/**
 * Digest a DWARF member through the same handle its UUID was read from, so a
 * member atomically replaced on disk cannot pair another file's digest with
 * the validated UUID. The read loop honors cancellation between chunks.
 */
const digestOpenHandle = async (
  handle: FileHandle,
  initial: Stats,
  signal: AbortSignal | undefined,
): Promise<Result<string, string>> => {
  const hash = createHash("sha256");
  const chunk = Buffer.allocUnsafe(64 * 1024);
  let position = 0;
  while (position < initial.size) {
    throwIfCancelled(signal);
    const observed = await handle.read(chunk, 0, chunk.length, position);
    if (observed.bytesRead === 0) break;
    hash.update(chunk.subarray(0, observed.bytesRead));
    position += observed.bytesRead;
  }
  const opened = await handle.stat();
  if (!sameFile(initial, opened))
    return err("the dSYM DWARF member changed while being read");
  return ok(hash.digest("hex"));
};

/**
 * Admit a caller-selected dSYM bundle for a detected Mach-O target: the
 * bundle must contain a DWARF member whose LC_UUID matches the UUID of the
 * target image slice REA selected for the requested architecture. Only the
 * matched member is retained for staging; a non-Mach-O or unreadable member
 * candidate (for example `.DS_Store`) is skipped, not fatal.
 */
export const admitDebugCompanion = async (input: {
  readonly dsymPath: string;
  readonly targetHandle: FileHandle;
  readonly targetSize: number;
  readonly architecture: BinaryArchitecture;
  readonly signal?: AbortSignal;
}): Promise<DebugCompanionAdmission> => {
  const { dsymPath, signal } = input;
  throwIfCancelled(signal);
  if (!isAbsolute(dsymPath))
    return err({
      reason:
        "dsym_path must be an absolute local filesystem path to a .dSYM bundle",
    });
  let bundle: Stats;
  try {
    bundle = await stat(dsymPath);
  } catch {
    return err({ reason: `dsym_path is not readable: ${dsymPath}` });
  }
  if (!bundle.isDirectory())
    return err({
      reason: `dsym_path is not a .dSYM bundle directory: ${dsymPath}`,
    });
  const dwarfDirectory = join(dsymPath, DSYM_DWARF_DIRECTORY);
  let names: string[];
  try {
    names = await readdir(dwarfDirectory);
  } catch {
    return err({
      reason: `dsym_path has no Contents/Resources/DWARF member directory: ${dsymPath}`,
    });
  }
  const memberPaths: string[] = [];
  for (const name of names) {
    const memberPath = join(dwarfDirectory, name);
    const memberStat = await stat(memberPath).catch(() => undefined);
    if (memberStat?.isFile() === true) memberPaths.push(memberPath);
  }
  if (memberPaths.length === 0)
    return err({
      reason: `dsym_path contains no DWARF member file: ${dsymPath}`,
    });
  const targetEntries = await readMachoFileUuidEntries(
    input.targetHandle,
    input.targetSize,
  );
  if (!targetEntries.ok) return err({ reason: targetEntries.error });
  const selectedCpuTypes = CPU_TYPES[input.architecture];
  const selectedUuids = targetEntries.value
    .filter(({ cpuType }) => selectedCpuTypes.includes(cpuType))
    .map(({ uuid }) => uuid);
  if (selectedUuids.length === 0)
    return err({
      reason: `the target image declares no LC_UUID for the selected ${input.architecture} slice`,
    });
  for (const memberPath of memberPaths) {
    throwIfCancelled(signal);
    const memberHandle = await open(memberPath, constants.O_RDONLY).catch(
      () => undefined,
    );
    if (memberHandle === undefined) continue;
    try {
      const initial = await memberHandle.stat();
      if (!initial.isFile()) continue;
      const memberEntries = await readMachoFileUuidEntries(
        memberHandle,
        initial.size,
      );
      if (!memberEntries.ok) continue;
      const matched = debugCompanionMatches({
        executableUuids: selectedUuids,
        companionUuids: memberEntries.value.map(({ uuid }) => uuid),
      });
      if (!matched.ok) continue;
      const memberSha256 = await digestOpenHandle(
        memberHandle,
        initial,
        signal,
      );
      if (!memberSha256.ok) return err({ reason: memberSha256.error });
      return ok({
        sourcePath: dsymPath,
        memberPath,
        memberSha256: memberSha256.value,
        uuid: matched.value.uuid,
      });
    } finally {
      await memberHandle.close();
    }
  }
  return err({
    reason:
      "dsym_path contains no Mach-O DWARF member whose LC_UUID matches the selected target slice",
  });
};
