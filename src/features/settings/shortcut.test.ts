import { describe, expect, it } from "vitest";
import { acceleratorFromEvent, type KeyLike } from "./shortcut";

const ev = (o: Partial<KeyLike>): KeyLike => ({
  key: "",
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  metaKey: false,
  ...o,
});

describe("acceleratorFromEvent", () => {
  it("builds the default panic shortcut from the physical key", () => {
    expect(acceleratorFromEvent(ev({ key: "L", code: "KeyL", ctrlKey: true, shiftKey: true }))).toBe("Ctrl+Shift+L");
  });

  it("is layout independent (Arabic layout)", () => {
    expect(acceleratorFromEvent(ev({ key: "ل", code: "KeyL", ctrlKey: true, shiftKey: true }))).toBe("Ctrl+Shift+L");
  });

  it("rejects lone modifiers", () => {
    for (const key of ["Control", "Shift", "Alt", "Meta", "AltGraph"]) {
      expect(acceleratorFromEvent(ev({ key, ctrlKey: true }))).toBeNull();
    }
  });

  it("requires ctrl, alt or meta", () => {
    expect(acceleratorFromEvent(ev({ key: "L", code: "KeyL", shiftKey: true }))).toBeNull();
    expect(acceleratorFromEvent(ev({ key: "L", code: "KeyL" }))).toBeNull();
  });

  it("accepts function keys, digits and named keys", () => {
    expect(acceleratorFromEvent(ev({ key: "F9", altKey: true }))).toBe("Alt+F9");
    expect(acceleratorFromEvent(ev({ key: "1", code: "Digit1", ctrlKey: true, altKey: true }))).toBe("Ctrl+Alt+1");
    expect(acceleratorFromEvent(ev({ key: " ", ctrlKey: true }))).toBe("Ctrl+Space");
    expect(acceleratorFromEvent(ev({ key: "PageUp", ctrlKey: true }))).toBe("Ctrl+PageUp");
  });

  it("rejects unsupported keys", () => {
    expect(acceleratorFromEvent(ev({ key: "F13", ctrlKey: true }))).toBeNull();
    expect(acceleratorFromEvent(ev({ key: "Enter", ctrlKey: true }))).toBeNull();
  });

  it("orders modifiers consistently", () => {
    // Five parts (all four modifiers + key) exceed the supported 2–4.
    expect(acceleratorFromEvent(ev({ key: "K", code: "KeyK", metaKey: true, shiftKey: true, altKey: true, ctrlKey: true }))).toBeNull();
    expect(acceleratorFromEvent(ev({ key: "K", code: "KeyK", metaKey: true, shiftKey: true, ctrlKey: true }))).toBe("Ctrl+Shift+Super+K");
  });
});
