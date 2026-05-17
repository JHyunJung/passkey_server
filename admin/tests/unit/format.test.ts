import { describe, expect, it } from "vitest";
import { formatPercent, lastN } from "@/lib/format";

describe("lastN", () => {
  it("returns em-dash for empty/null", () => {
    expect(lastN(null)).toBe("—");
    expect(lastN(undefined)).toBe("—");
    expect(lastN("")).toBe("—");
  });
  it("returns input unchanged when shorter than n", () => {
    expect(lastN("abc", 8)).toBe("abc");
  });
  it("prefixes with ellipsis when longer", () => {
    expect(lastN("0123456789abcdef", 8)).toBe("…89abcdef");
  });
});

describe("formatPercent", () => {
  it("dashes on zero denominator", () => {
    expect(formatPercent(5, 0)).toBe("—");
  });
  it("computes one-decimal percent", () => {
    expect(formatPercent(33, 100)).toBe("33.0%");
  });
});
