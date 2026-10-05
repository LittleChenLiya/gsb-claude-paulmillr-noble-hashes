import { describe, it } from "@paulmillr/jsbt/test.js";
import { deepStrictEqual as eql, throws } from "node:assert";
import { sha256 } from "../src/sha2.ts";
import {
  createStructHasher,
  encodeField,
  structDigest,
  STRUCT_VERSION,
  TAG_BYTES,
  TAG_STRING,
  TAG_UINT,
} from "../src/struct.ts";
import { bytesToHex } from "../src/utils.ts";

describe("struct", () => {
  it("empty digest equals sha256 of protocol version", () => {
    const got = structDigest([]);
    const want = sha256(new Uint8Array([STRUCT_VERSION]));
    eql(got, want);
  });

  it("ab+c differs from a+bc (length prefix disambiguates)", () => {
    const ab_c = structDigest([
      { name: "f1", type: "string", value: "ab" },
      { name: "f2", type: "string", value: "c" },
    ]);
    const a_bc = structDigest([
      { name: "f1", type: "string", value: "a" },
      { name: "f2", type: "string", value: "bc" },
    ]);
    eql(bytesToHex(ab_c) !== bytesToHex(a_bc), true, "digests must differ");
  });

  it("string 1 differs from integer 1 (type tag disambiguates)", () => {
    const str = structDigest([{ name: "x", type: "string", value: "1" }]);
    const int = structDigest([{ name: "x", type: "uint", value: 1 }]);
    eql(bytesToHex(str) !== bytesToHex(int), true, "digests must differ");
  });

  it("field order is meaningful", () => {
    const a_b = structDigest([
      { name: "a", type: "uint", value: 1 },
      { name: "b", type: "uint", value: 2 },
    ]);
    const b_a = structDigest([
      { name: "b", type: "uint", value: 2 },
      { name: "a", type: "uint", value: 1 },
    ]);
    eql(bytesToHex(a_b) !== bytesToHex(b_a), true, "digests must differ");
  });

  it("encoding failure does not update incremental state", () => {
    const good = createStructHasher();
    good.field("a", "uint", 5);
    const before = good.digest();

    const bad = createStructHasher();
    bad.field("a", "uint", 5);
    throws(() => bad.field("b", "uint", -1));
    const after = bad.digest();

    eql(after, before, "state digest must be unchanged after failed field");
  });

  it("encoding failure does not update seen-name set", () => {
    const h = createStructHasher();
    h.field("a", "uint", 1);
    throws(() => h.field("b", "uint", -1));
    h.field("b", "uint", 2);
    h.digest();
  });

  it("duplicate field names are rejected", () => {
    const h = createStructHasher();
    h.field("a", "uint", 1);
    throws(() => h.field("a", "string", "x"));
  });

  it("duplicate names rejected in one-shot", () => {
    throws(() =>
      structDigest([
        { name: "a", type: "uint", value: 1 },
        { name: "a", type: "uint", value: 2 },
      ])
    );
  });

  it("rejects invalid uint values", () => {
    throws(() => structDigest([{ name: "x", type: "uint", value: -1 }]));
    throws(() => structDigest([{ name: "x", type: "uint", value: 1.5 }]));
    throws(() => structDigest([{ name: "x", type: "uint", value: NaN }]));
    throws(() => structDigest([{ name: "x", type: "uint", value: Infinity }]));
    throws(() => structDigest([{ name: "x", type: "uint", value: -1n }]));
  });

  it("rejects wrong value types", () => {
    throws(() => structDigest([{ name: "x", type: "bytes", value: "abc" }]));
    throws(() => structDigest([{ name: "x", type: "string", value: 123 }]));
    throws(() => structDigest([{ name: "x", type: "uint", value: "1" }]));
    throws(() => structDigest([{ name: "x", type: "uint", value: true }]));
  });

  it("rejects invalid field names", () => {
    throws(() => structDigest([{ name: 123 as any, type: "uint", value: 1 }]));
    throws(() => structDigest([{ name: null as any, type: "uint", value: 1 }]));
  });

  it("rejects unknown field type", () => {
    throws(() => structDigest([{ name: "x", type: "unknown" as any, value: 1 }]));
  });

  it("uint encodes as minimal big-endian bytes", () => {
    // name_len=1, name="u"(0x75), tag=uint(0x03), value_len, value
    eql(encodeField("u", "uint", 0), Uint8Array.from([0x00, 0x01, 0x75, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00]));
    eql(encodeField("u", "uint", 1), Uint8Array.from([0x00, 0x01, 0x75, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01]));
    eql(encodeField("u", "uint", 256), Uint8Array.from([0x00, 0x01, 0x75, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00]));
  });

  it("uint accepts bigint", () => {
    const a = structDigest([{ name: "big", type: "uint", value: 123456789012345678901234567890n }]);
    const b = structDigest([{ name: "big", type: "uint", value: 123456789012345678901234567890n }]);
    eql(a, b);
    const c = structDigest([{ name: "n", type: "uint", value: 42 }]);
    const d = structDigest([{ name: "n", type: "uint", value: 42n }]);
    eql(c, d);
  });

  it("bytes field round-trips", () => {
    const value = new Uint8Array([0, 1, 2, 255, 128]);
    const got = structDigest([{ name: "b", type: "bytes", value }]);
    const want = sha256
      .create()
      .update(new Uint8Array([STRUCT_VERSION]))
      .update(encodeField("b", "bytes", value))
      .digest();
    eql(got, want);
  });

  it("string field is UTF-8 encoded", () => {
    const got = structDigest([{ name: "s", type: "string", value: "cafe" }]);
    const want = sha256
      .create()
      .update(new Uint8Array([STRUCT_VERSION]))
      .update(encodeField("s", "string", "cafe"))
      .digest();
    eql(got, want);
  });

  it("encodeField layout is self-describing", () => {
    const enc = encodeField("ab", "string", "c");
    eql(enc, Uint8Array.from([0x00, 0x02, 0x61, 0x62, TAG_STRING, 0x00, 0x00, 0x00, 0x01, 0x63]));
  });

  it("type tags are distinct", () => {
    eql(TAG_BYTES !== TAG_STRING, true);
    eql(TAG_STRING !== TAG_UINT, true);
    eql(TAG_BYTES !== TAG_UINT, true);
  });

  it("name length overflow is rejected", () => {
    const longName = "a".repeat(65536);
    throws(() => encodeField(longName, "uint", 1));
  });

  it("value length overflow is rejected for bytes", () => {
    const fake = { length: 0x100000000 } as unknown as Uint8Array;
    throws(() => encodeField("x", "bytes", fake));
  });

  it("digest cannot be called twice", () => {
    const h = createStructHasher();
    h.field("a", "uint", 1);
    h.digest();
    throws(() => h.digest());
  });

  it("field cannot be added after digest", () => {
    const h = createStructHasher();
    h.digest();
    throws(() => h.field("a", "uint", 1));
  });

  it("one-shot and incremental produce the same digest", () => {
    const fields = [
      { name: "id", type: "uint" as const, value: 7 },
      { name: "name", type: "string" as const, value: "alice" },
      { name: "data", type: "bytes" as const, value: new Uint8Array([1, 2, 3]) },
    ];
    const one = structDigest(fields);
    const inc = createStructHasher();
    for (const f of fields) inc.field(f.name, f.type, f.value);
    eql(inc.digest(), one);
  });

  it("small vectors", () => {
    const vectors: { fields: Parameters<typeof structDigest>[0]; hex: string }[] = [
      { fields: [], hex: "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a" },
      {
        fields: [{ name: "x", type: "uint", value: 0 }],
        hex: "131fd78f8cc7b616b2d9cc272d45476dc343b6a6e0f1bd7d4ca1c42c0cd0418f",
      },
    ];
    for (const v of vectors) {
      eql(bytesToHex(structDigest(v.fields)), v.hex);
    }
  });
});

it.runWhen(import.meta.url);
