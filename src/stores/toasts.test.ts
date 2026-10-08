import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useToasts } from "./toasts";

beforeEach(() => {
  vi.useFakeTimers();
  useToasts.setState({ toasts: [] });
});
afterEach(() => vi.useRealTimers());

describe("toasts", () => {
  it("de-duplicates identical messages", () => {
    useToasts.getState().push("info", "hi");
    useToasts.getState().push("info", "hi");
    expect(useToasts.getState().toasts).toHaveLength(1);
  });
  it("keeps at most three", () => {
    for (const m of ["a", "b", "c", "d"]) useToasts.getState().push("info", m);
    expect(useToasts.getState().toasts.map((t) => t.message)).toEqual(["b", "c", "d"]);
  });
  it("expires", () => {
    useToasts.getState().push("success", "done");
    vi.advanceTimersByTime(4000);
    expect(useToasts.getState().toasts).toHaveLength(0);
  });
});
