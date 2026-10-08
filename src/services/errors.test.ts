import { describe, expect, it } from "vitest";
import { AppError, isCode, toAppError } from "./errors";

describe("toAppError", () => {
  it("keeps known codes and details", () => {
    const e = toAppError({ code: "WRONG_PASSWORD", details: "x" });
    expect(e.code).toBe("WRONG_PASSWORD");
    expect(e.details).toBe("x");
  });
  it("maps unknown codes, strings and junk to INTERNAL", () => {
    expect(toAppError({ code: "NOPE" }).code).toBe("INTERNAL");
    expect(toAppError("command foo not found").code).toBe("INTERNAL");
    expect(toAppError(undefined).code).toBe("INTERNAL");
    expect(toAppError(42).code).toBe("INTERNAL");
  });
  it("passes AppError through", () => {
    const e = new AppError("CORRUPTED");
    expect(toAppError(e)).toBe(e);
    expect(isCode(e, "CORRUPTED", "IO")).toBe(true);
    expect(isCode(e, "IO")).toBe(false);
  });
});
