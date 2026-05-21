import { describe, expect, it } from "vitest";
import {
  formatCount,
  formatMaybeCount,
  formatPercent,
  lastN,
} from "@/lib/format";

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

describe("formatCount", () => {
  it("groups thousands", () => {
    expect(formatCount(1234567)).toBe("1,234,567");
  });
  it("leaves small numbers unchanged", () => {
    expect(formatCount(0)).toBe("0");
    expect(formatCount(42)).toBe("42");
  });
});

describe("formatMaybeCount", () => {
  it("returns em-dash for null/undefined", () => {
    expect(formatMaybeCount(null)).toBe("—");
    expect(formatMaybeCount(undefined)).toBe("—");
  });
  it("formats a present number", () => {
    expect(formatMaybeCount(1234)).toBe("1,234");
    expect(formatMaybeCount(0)).toBe("0");
  });
});
