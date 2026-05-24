import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { AaguidLabel } from "@/components/AaguidLabel";

describe("AaguidLabel", () => {
  it("renders MDS label without 미등록 badge when fromMds=true", () => {
    render(
      <AaguidLabel
        aaguid={{
          aaguid: "11111111-1111-1111-1111-111111111111",
          displayName: "YubiKey 5C",
          fromMds: true,
        }}
      />,
    );
    expect(screen.getByText("YubiKey 5C")).toBeInTheDocument();
    expect(screen.queryByText("미등록")).not.toBeInTheDocument();
  });

  it("renders raw uuid with 미등록 badge when fromMds=false", () => {
    render(
      <AaguidLabel
        aaguid={{
          aaguid: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
          displayName: "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4",
          fromMds: false,
        }}
      />,
    );
    expect(screen.getByText(/ea9b8d66/)).toBeInTheDocument();
    expect(screen.getByText("미등록")).toBeInTheDocument();
  });

  it("renders 'unknown' for null aaguid", () => {
    render(
      <AaguidLabel
        aaguid={{ aaguid: null, displayName: "unknown", fromMds: false }}
      />,
    );
    expect(screen.getByText("unknown")).toBeInTheDocument();
  });
});
