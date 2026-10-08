import type { AppErrorPayload, ErrorCode } from "@/types/api";

const KNOWN: ReadonlySet<string> = new Set<ErrorCode>([
  "WRONG_PASSWORD",
  "INVALID_RECOVERY_KEY",
  "CORRUPTED",
  "UNSUPPORTED",
  "NOT_A_CONTAINER",
  "NO_SPACE",
  "PERMISSION_DENIED",
  "FILE_IN_USE",
  "OUTPUT_EXISTS",
  "NOT_FOUND",
  "VAULT_LOCKED",
  "CANCELLED",
  "VERIFICATION_FAILED",
  "SOURCE_CHANGED",
  "INVALID_INPUT",
  "UNSAFE_PATH",
  "STORAGE",
  "BUSY",
  "IO",
  "INTERNAL",
]);

/** A backend error with a stable code. UI text is derived from the code, never from `details`. */
export class AppError extends Error {
  readonly code: ErrorCode;
  readonly details?: string;

  constructor(code: ErrorCode, details?: string) {
    super(code);
    this.name = "AppError";
    this.code = code;
    this.details = details;
  }
}

function isPayload(v: unknown): v is AppErrorPayload {
  return (
    typeof v === "object" &&
    v !== null &&
    "code" in v &&
    typeof (v as { code: unknown }).code === "string"
  );
}

/** Turn whatever `invoke` rejected with into an `AppError`. Unknown shapes become INTERNAL so
 * the UI never shows a raw string from the bridge. */
export function toAppError(e: unknown): AppError {
  if (e instanceof AppError) return e;
  if (isPayload(e)) {
    const code = KNOWN.has(e.code) ? e.code : "INTERNAL";
    return new AppError(code, typeof e.details === "string" ? e.details : undefined);
  }
  if (typeof e === "string") {
    // Tauri reports unknown-command / argument-shape failures as plain strings.
    return new AppError("INTERNAL", e);
  }
  return new AppError("INTERNAL");
}

export function fromPayload(p: AppErrorPayload | null | undefined): AppError | null {
  return p ? toAppError(p) : null;
}

export function isCode(e: unknown, ...codes: ErrorCode[]): boolean {
  return e instanceof AppError && codes.includes(e.code);
}
