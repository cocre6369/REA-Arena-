import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readdir, stat } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import type { FileHandle } from "node:fs/promises";

import { err, ok, type Result } from "../domain/result.js";
import type { MachODebugCompanion } from "../domain/binaryTargetTypes.js";
import {
  debugCompanionMatches,
  readMachoUuids,
} from "../domain/machoDebugCompanion.js";

/** Bound on the bytes read to walk Mach-O headers and load commands. */
const HEADER_READ_LIMIT = 64 * 1024;

const DSYM_DWARF_DIRECTORY = join("Contents", "Resources", "DWARF");

/** Admitted identity of a caller-selected dSYM companion. */
export type DebugCompanionAdmission = Result<
  MachODebugCompanion,
  DebugCompanionRejection
>;

/** Why a caller-selected debug companion was refused, in caller-facing words. */
export interface DebugCompanionRejection {
  readonly reason: string;
}

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
 * Read every LC_UUID of a Mach-O file: a thin image from its start, or each
 * slice of a universal container from its table.
 */
export const readMachoFileUuids = async (
  handle: FileHandle,
  fileSize: number,
): Promise<Result<string[], string>> => {
  const prefix = await readUuidWindow(handle, 0, fileSize);
  if (!prefix.ok) return prefix;
  const magic = prefix.value.length >= 4 ? prefix.value.readUInt32BE(0) : 0;
  if (magic !== 0xcafebabe && magic !== 0xcafebabf) {
    const thin = readMachoUuids(prefix.value);
    return thin.ok && thin.value.length > 0
      ? thin
      : thin.ok
        ? err("the Mach-O target declares no LC_UUID")
        : thin;
  }
  const wide = magic === 0xcafebabf;
  if (prefix.value.length < 8)
    return err("the universal Mach-O container header is truncated");
  const count = prefix.value.readUInt32BE(4);
  const entrySize = wide ? 32 : 20;
  if (count > 128 || 8 + count * entrySize > prefix.value.length)
    return err("the universal Mach-O container table is truncated");
  const uuids: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const entry = 8 + index * entrySize;
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
    const read = readMachoUuids(slice.value);
    if (!read.ok) return read;
    uuids.push(...read.value);
  }
  return ok(uuids);
};

const digestFile = async (path: string): Promise<string> => {
  const handle = await open(path, constants.O_RDONLY);
  try {
    const hash = createHash("sha256");
    const chunk = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    for (;;) {
      const observed = await handle.read(chunk, 0, chunk.length, position);
      if (observed.bytesRead === 0) break;
      hash.update(chunk.subarray(0, observed.bytesRead));
      position += observed.bytesRead;
    }
    return hash.digest("hex");
  } finally {
    await handle.close();
  }
};

/**
 * Admit a caller-selected dSYM bundle for a detected Mach-O target: the
 * bundle must contain a DWARF member whose LC_UUID matches a UUID of the
 * target image. Only the matched member is retained for staging.
 */
export const admitDebugCompanion = async (input: {
  readonly dsymPath: string;
  readonly targetHandle: FileHandle;
  readonly targetSize: number;
}): Promise<DebugCompanionAdmission> => {
  const { dsymPath } = input;
  if (!isAbsolute(dsymPath))
    return err({
      reason:
        "dsym_path must be an absolute local filesystem path to a .dSYM bundle",
    });
  let bundle: Awaited<ReturnType<typeof stat>>;
  try {
    bundle = await stat(dsymPath);
  } catch {
    return err({
      reason: `dsym_path is not readable: ${dsymPath}`,
    });
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
  const members: string[] = [];
  for (const name of names) {
    const memberPath = join(dwarfDirectory, name);
    const memberStat = await stat(memberPath).catch(() => undefined);
    if (memberStat?.isFile() === true) members.push(memberPath);
  }
  if (members.length === 0)
    return err({
      reason: `dsym_path contains no DWARF member file: ${dsymPath}`,
    });
  const targetUuids = await readMachoFileUuids(
    input.targetHandle,
    input.targetSize,
  );
  if (!targetUuids.ok) return err({ reason: targetUuids.error });
  for (const memberPath of members) {
    const memberHandle = await open(memberPath, constants.O_RDONLY).catch(
      () => undefined,
    );
    if (memberHandle === undefined)
      return err({
        reason: `dsym DWARF member is not readable: ${memberPath}`,
      });
    try {
      const size = (await memberHandle.stat()).size;
      const memberUuids = await readMachoFileUuids(memberHandle, size);
      if (!memberUuids.ok)
        return err({
          reason: `dsym DWARF member could not be read as Mach-O: ${memberPath} (${memberUuids.error})`,
        });
      const matched = debugCompanionMatches({
        executableUuids: targetUuids.value,
        companionUuids: memberUuids.value,
      });
      if (matched.ok)
        return ok({
          sourcePath: dsymPath,
          memberPath,
          memberSha256: await digestFile(memberPath),
          uuid: matched.value.uuid,
        });
    } finally {
      await memberHandle.close();
    }
  }
  return err({
    reason:
      "dsym_path contains no DWARF member whose LC_UUID matches the target image",
  });
};
