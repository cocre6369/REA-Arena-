import { describe, expect, it } from "vitest";

import {
  debugCompanionMatches,
  readMachoUuids,
} from "./machoDebugCompanion.js";

const uuidBytes = (text: string): Buffer =>
  Buffer.from(text.replace(/-/gu, ""), "hex");

const withUuidLoadCommand = (uuid: string): Buffer => {
  const commandSize = 8 + 16;
  const bytes = Buffer.alloc(32 + commandSize);
  bytes.writeUInt32LE(0xfeedfacf, 0); // 64-bit little-endian thin image
  bytes.writeUInt32LE(0x0100000c, 4); // cputype arm64
  bytes.writeUInt32LE(0, 8); // cpusubtype
  bytes.writeUInt32LE(2, 12); // MH_EXECUTE
  bytes.writeUInt32LE(1, 16); // ncmds
  bytes.writeUInt32LE(commandSize, 20); // sizeofcmds
  bytes.writeUInt32LE(0, 24); // flags
  bytes.writeUInt32LE(0, 28); // reserved (64-bit header)
  bytes.writeUInt32LE(0x1b, 32); // LC_UUID
  bytes.writeUInt32LE(commandSize, 36);
  uuidBytes(uuid).copy(bytes, 40);
  return bytes;
};

const universalWithSlices = (slices: readonly Buffer[]): Buffer => {
  const headerSize = 8 + slices.length * 20;
  const total = slices.reduce((size, slice) => size + slice.length, headerSize);
  const bytes = Buffer.alloc(total);
  bytes.writeUInt32BE(0xcafebabe, 0);
  bytes.writeUInt32BE(slices.length, 4);
  let offset = headerSize;
  slices.forEach((slice, index) => {
    const entry = 8 + index * 20;
    bytes.writeInt32BE(0x01000007, entry); // cputype x86_64
    bytes.writeInt32BE(3, entry + 4);
    bytes.writeUInt32BE(offset, entry + 8);
    bytes.writeUInt32BE(slice.length, entry + 12);
    bytes.writeUInt32BE(12, entry + 16);
    slice.copy(bytes, offset);
    offset += slice.length;
  });
  return bytes;
};

describe("Mach-O LC_UUID reading", () => {
  it("reads the UUID of a thin image", () => {
    const bytes = withUuidLoadCommand("A1B2C3D4-E5F6-0789-ABCD-EF0123456789");
    expect(readMachoUuids(bytes)).toEqual({
      ok: true,
      value: ["A1B2C3D4-E5F6-0789-ABCD-EF0123456789"],
    });
  });
  it("reports images with no LC_UUID as an empty list", () => {
    const bytes = Buffer.alloc(28);
    bytes.writeUInt32LE(0xfeedface, 0); // 32-bit image, ncmds 0
    bytes.writeUInt32LE(0, 16);
    expect(readMachoUuids(bytes)).toEqual({ ok: true, value: [] });
  });
  it("descends into universal containers and keeps slice order", () => {
    const container = universalWithSlices([
      withUuidLoadCommand("11111111-1111-1111-1111-111111111111"),
      withUuidLoadCommand("22222222-2222-2222-2222-222222222222"),
    ]);
    expect(readMachoUuids(container)).toEqual({
      ok: true,
      value: [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
      ],
    });
  });
  it.each([
    ["short buffer", Buffer.alloc(4)],
    [
      "truncated load command",
      (() => {
        const bytes = Buffer.alloc(28);
        bytes.writeUInt32LE(0xfeedfacf, 0);
        bytes.writeUInt32LE(1, 16); // one command that the header does not contain
        return bytes;
      })(),
    ],
    [
      "out-of-bounds universal slice",
      (() => {
        const bytes = Buffer.alloc(28);
        bytes.writeUInt32BE(0xcafebabe, 0);
        bytes.writeUInt32BE(1, 4);
        bytes.writeUInt32BE(0x1000, 8 + 8); // offset far past the buffer
        bytes.writeUInt32BE(0x100, 8 + 12);
        return bytes;
      })(),
    ],
  ])("rejects a %s", (_name, bytes) => {
    expect(readMachoUuids(bytes).ok).toBe(false);
  });
});

describe("debug companion UUID matching", () => {
  const uuid = "A1B2C3D4-E5F6-0789-ABCD-EF0123456789";

  it("matches when the companion carries the executable UUID", () => {
    expect(
      debugCompanionMatches({
        executableUuids: [uuid],
        companionUuids: [uuid],
      }),
    ).toEqual({ ok: true, value: { uuid } });
  });
  it("rejects a mismatch with a named reason", () => {
    const result = debugCompanionMatches({
      executableUuids: [uuid],
      companionUuids: ["99999999-9999-9999-9999-999999999999"],
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected rejection");
    expect(result.error).toContain("does not match");
  });
  it("rejects executables without a usable LC_UUID", () => {
    const result = debugCompanionMatches({
      executableUuids: ["00000000-0000-0000-0000-000000000000"],
      companionUuids: ["00000000-0000-0000-0000-000000000000"],
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected rejection");
    expect(result.error).toContain("no LC_UUID");
  });
  it("matches one universal companion slice against the executable", () => {
    expect(
      debugCompanionMatches({
        executableUuids: [uuid],
        companionUuids: ["88888888-8888-8888-8888-888888888888", uuid],
      }),
    ).toEqual({ ok: true, value: { uuid } });
  });
});
