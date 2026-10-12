import { err, ok, type Result } from "./result.js";

const LC_UUID = 0x1b;
const FAT_MAGIC_BE = 0xcafebabe;
const FAT_MAGIC_64_BE = 0xcafebabf;
const THIN_MAGICS = new Set([0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe]);
const UUID_BYTES = 16;

const formatUuid = (raw: Buffer): string => {
  const hex = raw.toString("hex").toUpperCase();
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-");
};

const readUuidsFromThin = (
  bytes: Buffer,
  offset: number,
  end: number,
): Result<string[], string> => {
  const base = offset;
  const magic = bytes.readUInt32BE(base);
  if (!THIN_MAGICS.has(magic))
    return err(`not a Mach-O image at offset ${String(offset)}`);
  const wide = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const commandsOffset = base + (wide ? 32 : 28);
  if (commandsOffset > end)
    return err("Mach-O header is truncated before its load commands");
  const commandCount = bytes.readUInt32LE(base + 16);
  let cursor = commandsOffset;
  const uuids: string[] = [];
  for (let index = 0; index < commandCount; index += 1) {
    if (cursor + 8 > end)
      return err(`Mach-O load command ${String(index)} is truncated`);
    const command = bytes.readUInt32LE(cursor);
    const size = bytes.readUInt32LE(cursor + 4);
    if (size < 8 || cursor + size > end)
      return err(`Mach-O load command ${String(index)} has an invalid size`);
    if (command === LC_UUID) {
      if (size < 8 + UUID_BYTES)
        return err("LC_UUID load command is truncated");
      uuids.push(
        formatUuid(bytes.subarray(cursor + 8, cursor + 8 + UUID_BYTES)),
      );
    }
    cursor += size;
  }
  return ok(uuids);
};

/**
 * Read every LC_UUID of a Mach-O image, descending into universal (FAT)
 * containers. A zero UUID is preserved: it is an observed value, not an
 * unknown, and a caller-selected companion must not match it accidentally.
 */
export const readMachoUuids = (bytes: Buffer): Result<string[], string> => {
  if (bytes.length < 8) return err("Mach-O image is truncated");
  const magic = bytes.readUInt32BE(0);
  if (magic === FAT_MAGIC_BE || magic === FAT_MAGIC_64_BE) {
    const wide = magic === FAT_MAGIC_64_BE;
    const count = bytes.readUInt32BE(4);
    const entrySize = wide ? 32 : 20;
    if (count > 128 || 8 + count * entrySize > bytes.length)
      return err(
        "universal Mach-O container has an invalid architecture table",
      );
    const uuids: string[] = [];
    for (let index = 0; index < count; index += 1) {
      const entry = 8 + index * entrySize;
      const sliceOffset = wide
        ? Number(bytes.readBigUInt64BE(entry + 8))
        : bytes.readUInt32BE(entry + 8);
      const sliceSize = wide
        ? Number(bytes.readBigUInt64BE(entry + 16))
        : bytes.readUInt32BE(entry + 12);
      if (sliceSize === 0) return err("universal Mach-O slice is empty");
      if (sliceOffset > bytes.length || sliceSize > bytes.length - sliceOffset)
        return err("universal Mach-O slice is out of bounds");
      const slice = readUuidsFromThin(
        bytes,
        sliceOffset,
        sliceOffset + sliceSize,
      );
      if (!slice.ok) return slice;
      uuids.push(...slice.value);
    }
    return ok(uuids);
  }
  return readUuidsFromThin(bytes, 0, bytes.length);
};

/**
 * A companion matches when it carries the UUID of the executable image REA
 * will analyze. Executable images without any LC_UUID cannot be matched and
 * are rejected explicitly instead of matching vacuously. An all-zero UUID is
 * an observed placeholder, not an identity, and never matches.
 */
const ZERO_UUID = "00000000-0000-0000-0000-000000000000";

export const debugCompanionMatches = (input: {
  readonly executableUuids: readonly string[];
  readonly companionUuids: readonly string[];
}): Result<{ readonly uuid: string }, string> => {
  const executable = input.executableUuids.filter((uuid) => uuid !== ZERO_UUID);
  if (executable.length === 0)
    return err("the executable declares no LC_UUID to match against");
  const companions = new Set(
    input.companionUuids.filter((uuid) => uuid !== ZERO_UUID),
  );
  for (const uuid of executable) if (companions.has(uuid)) return ok({ uuid });
  return err(
    "the debug companion's UUID does not match the executable's LC_UUID",
  );
};
