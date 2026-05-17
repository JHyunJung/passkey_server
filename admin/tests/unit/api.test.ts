import { describe, expect, it } from "vitest";
import { PasskeyAdminError, unwrap } from "@/lib/api";
import type { ApiEnvelope } from "@/types/api";

function mkResponse<T>(env: ApiEnvelope<T>, status = 200) {
  return {
    data: env,
    status,
    statusText: status === 200 ? "OK" : "ERR",
    headers: {},
    config: {} as never,
  };
}

describe("unwrap", () => {
  it("returns data when envelope success=true", () => {
    const res = mkResponse({
      success: true,
      code: "OK",
      message: "Success",
      data: { hello: "world" },
      timestamp: "2026-05-16T00:00:00",
    });
    expect(unwrap(res)).toEqual({ hello: "world" });
  });

  it("throws PasskeyAdminError when envelope success=false", () => {
    const res = mkResponse({
      success: false,
      code: "T004",
      message: "Tenant slug already exists",
      timestamp: "2026-05-16T00:00:00",
      error: { errorCode: "T004" },
    });
    expect(() => unwrap(res)).toThrow(PasskeyAdminError);
    try {
      unwrap(res);
    } catch (e) {
      expect((e as PasskeyAdminError).code).toBe("T004");
      expect((e as PasskeyAdminError).message).toBe("Tenant slug already exists");
    }
  });

  it("treats null data as ok (e.g. logout)", () => {
    const res = mkResponse<null>({
      success: true,
      code: "OK",
      message: "Logged out",
      data: null,
      timestamp: "2026-05-16T00:00:00",
    });
    expect(unwrap(res)).toBeNull();
  });
});
