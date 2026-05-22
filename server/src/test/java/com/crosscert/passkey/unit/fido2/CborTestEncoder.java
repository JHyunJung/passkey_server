package com.crosscert.passkey.unit.fido2;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Minimal CBOR encoder — test-only. Production code never encodes CBOR (the server only decodes
 * authenticator output), so this lives under src/test and exists purely to build fixtures for the
 * {@code fido2} decoder/verifier tests.
 */
public final class CborTestEncoder {

  private CborTestEncoder() {}

  public static byte[] encodeMap(Map<Object, Object> map) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeTypeAndLength(out, 5, map.size());
    for (Map.Entry<Object, Object> e : map.entrySet()) {
      writeItem(out, e.getKey());
      writeItem(out, e.getValue());
    }
    return out.toByteArray();
  }

  public static byte[] encode(Object value) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeItem(out, value);
    return out.toByteArray();
  }

  private static void writeItem(ByteArrayOutputStream out, Object value) {
    if (value instanceof Long l) {
      if (l >= 0) {
        writeTypeAndLength(out, 0, l);
      } else {
        writeTypeAndLength(out, 1, -1 - l);
      }
    } else if (value instanceof Integer i) {
      writeItem(out, (long) i);
    } else if (value instanceof byte[] b) {
      writeTypeAndLength(out, 2, b.length);
      out.write(b, 0, b.length);
    } else if (value instanceof String s) {
      byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
      writeTypeAndLength(out, 3, utf8.length);
      out.write(utf8, 0, utf8.length);
    } else if (value instanceof List<?> list) {
      writeTypeAndLength(out, 4, list.size());
      for (Object item : list) {
        writeItem(out, item);
      }
    } else if (value instanceof Map<?, ?> m) {
      writeTypeAndLength(out, 5, m.size());
      for (Map.Entry<?, ?> e : m.entrySet()) {
        writeItem(out, e.getKey());
        writeItem(out, e.getValue());
      }
    } else if (value instanceof Boolean bool) {
      out.write(0xe0 | (bool ? 21 : 20));
    } else if (value == null) {
      out.write(0xf6);
    } else {
      throw new IllegalArgumentException("unsupported test CBOR value: " + value);
    }
  }

  private static void writeTypeAndLength(ByteArrayOutputStream out, int majorType, long len) {
    int mt = majorType << 5;
    if (len < 24) {
      out.write(mt | (int) len);
    } else if (len < 256) {
      out.write(mt | 24);
      out.write((int) len);
    } else if (len < 65536) {
      out.write(mt | 25);
      out.write((int) (len >> 8));
      out.write((int) (len & 0xff));
    } else {
      out.write(mt | 26);
      out.write((int) (len >> 24));
      out.write((int) (len >> 16) & 0xff);
      out.write((int) (len >> 8) & 0xff);
      out.write((int) (len & 0xff));
    }
  }
}
