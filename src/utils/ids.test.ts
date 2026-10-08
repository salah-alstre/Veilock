import { describe, expect, it } from "vitest";
import { baseName, dirName, newOpId } from "./ids";

describe("baseName", () => {
  it("handles both separators", () => {
    expect(baseName("C:\\Users\\me\\notes.txt")).toBe("notes.txt");
    expect(baseName("/home/me/notes.txt")).toBe("notes.txt");
  });
  it("ignores trailing separators and runs of them", () => {
    expect(baseName("C:\\data\\folder\\")).toBe("folder");
    expect(baseName("a//b///c")).toBe("c");
  });
  it("returns the input when there is nothing to split", () => {
    expect(baseName("plain")).toBe("plain");
    expect(baseName("")).toBe("");
  });
});

describe("dirName", () => {
  it("returns the parent", () => {
    expect(dirName("C:\\a\\b.txt")).toBe("C:\\a");
    expect(dirName("/a/b.txt")).toBe("/a");
    expect(dirName("b.txt")).toBe("b.txt");
  });
});

describe("newOpId", () => {
  it("is unique", () => {
    expect(newOpId()).not.toBe(newOpId());
  });
});
