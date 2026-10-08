import { afterEach, describe, expect, it, vi } from "vitest";
import { applyTheme, resolveTheme } from "./theme";

function mockMatchMedia(light: boolean): void {
  vi.stubGlobal("matchMedia", (q: string) => ({
    matches: light && q.includes("light"),
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  }));
  window.matchMedia = globalThis.matchMedia;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete document.documentElement.dataset.theme;
});

describe("theme", () => {
  it("resolves explicit settings directly", () => {
    expect(resolveTheme("dark")).toBe("dark");
    expect(resolveTheme("light")).toBe("light");
  });
  it("follows the OS for system", () => {
    mockMatchMedia(true);
    expect(resolveTheme("system")).toBe("light");
    mockMatchMedia(false);
    expect(resolveTheme("system")).toBe("dark");
  });
  it("sets data-theme on the root", () => {
    applyTheme("light");
    expect(document.documentElement.dataset.theme).toBe("light");
  });
});
