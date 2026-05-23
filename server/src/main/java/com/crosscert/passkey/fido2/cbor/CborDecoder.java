package com.crosscert.passkey.fido2.cbor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal CBOR (RFC 8949) decoder covering only the constructs WebAuthn uses: unsigned/negative
 * integers, byte strings, text strings, arrays, maps, and the false/true/null simple values.
 * Anything else (tags, floats, indefinite-length items) is rejected with {@link
 * CborDecodeException} so a malformed or hostile attestation cannot smuggle unexpected structure
 * past the verifier (fail-closed).
 */
public final class CborDecoder {

  /**
   * Maximum CBOR nesting depth. WebAuthn attestationObject/COSE structures nest only 5-6 levels; 32
   * is generous while still bounding recursion so a hostile input cannot trigger a {@link
   * StackOverflowError} (an {@code Error}, which callers cannot catch as {@link
   * CborDecodeException}).
   */
  private static final int MAX_DEPTH = 32;

  private final byte[] data;
  private int pos;

  private CborDecoder(byte[] data) {
    this.data = data;
    this.pos = 0;
  }

  /** Decode a single CBOR data item; the entire input must be consumed. */
  public static Object decode(byte[] data) {
    CborDecoder d = new CborDecoder(data);
    Object value = d.readItem(0);
    if (d.pos != data.length) {
      throw new CborDecodeException("trailing bytes after CBOR item");
    }
    return value;
  }

  /** Decode a single CBOR data item, allowing trailing bytes; reports how many were consumed. */
  public static DecodeResult decodeWithLength(byte[] data) {
    CborDecoder d = new CborDecoder(data);
    Object value = d.readItem(0);
    return new DecodeResult(value, d.pos);
  }

  /** A decoded value paired with the number of input bytes it occupied. */
  public record DecodeResult(Object value, int consumed) {}

  private Object readItem(int depth) {
    if (depth > MAX_DEPTH) {
      throw new CborDecodeException("CBOR nesting too deep");
    }
    int initial = readByte();
    int majorType = (initial >> 5) & 0x07;
    int additional = initial & 0x1f;
    return switch (majorType) {
      case 0 -> readUnsigned(additional);
      case 1 -> -1L - readUnsigned(additional);
      case 2 -> readBytes(readUnsigned(additional));
      case 3 -> new String(readBytes(readUnsigned(additional)), StandardCharsets.UTF_8);
      case 4 -> readArray(readUnsigned(additional), depth);
      case 5 -> readMap(readUnsigned(additional), depth);
      case 7 -> readSimple(additional);
      default -> throw new CborDecodeException("unsupported CBOR major type " + majorType);
    };
  }

  /**
   * Validate a declared collection/string length against the input that remains. Every CBOR data
   * item occupies at least one byte, so a length larger than the remaining bytes is impossible and
   * is rejected before any allocation. This also rejects lengths above {@code Integer.MAX_VALUE}
   * for free, since the remaining input can never exceed a 32-bit array size.
   */
  private int checkedLength(long len) {
    if (len < 0 || len > data.length - pos) {
      throw new CborDecodeException("CBOR length " + len + " exceeds remaining input");
    }
    return (int) len;
  }

  private long readUnsigned(int additional) {
    if (additional < 24) {
      return additional;
    }
    return switch (additional) {
      case 24 -> readByte() & 0xffL;
      case 25 -> readUint(2);
      case 26 -> readUint(4);
      case 27 -> readUint(8);
      default -> throw new CborDecodeException("unsupported CBOR additional info " + additional);
    };
  }

  private long readUint(int n) {
    long value = 0;
    for (int i = 0; i < n; i++) {
      value = (value << 8) | (readByte() & 0xffL);
    }
    if (value < 0) {
      throw new CborDecodeException("CBOR integer exceeds signed 64-bit range");
    }
    return value;
  }

  private List<Object> readArray(long rawLen, int depth) {
    int len = checkedLength(rawLen);
    List<Object> out = new ArrayList<>(len);
    for (int i = 0; i < len; i++) {
      out.add(readItem(depth + 1));
    }
    return out;
  }

  private Map<Object, Object> readMap(long rawLen, int depth) {
    // A map entry is a key plus a value (>= 2 bytes), so the array bound (>= 1 byte per item) is a
    // conservative, safe upper bound that still prevents pre-allocation memory bombs.
    int len = checkedLength(rawLen);
    Map<Object, Object> out = new LinkedHashMap<>();
    for (int i = 0; i < len; i++) {
      Object key = readItem(depth + 1);
      Object value = readItem(depth + 1);
      out.put(key, value);
    }
    return out;
  }

  private Object readSimple(int additional) {
    return switch (additional) {
      case 20 -> false;
      case 21 -> true;
      case 22 -> null;
      default -> throw new CborDecodeException("unsupported CBOR simple value " + additional);
    };
  }

  private int readByte() {
    if (pos >= data.length) {
      throw new CborDecodeException("unexpected end of CBOR input");
    }
    return data[pos++] & 0xff;
  }

  private byte[] readBytes(long rawLen) {
    int len = checkedLength(rawLen);
    byte[] out = new byte[len];
    System.arraycopy(data, pos, out, 0, len);
    pos += len;
    return out;
  }
}
