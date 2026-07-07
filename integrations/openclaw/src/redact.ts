/**
 * Secret redaction — mirror of the hermes `audit.py` / blackbox.ts sanitizer.
 * Reports NEVER carry raw content; evidence snippets are always run through
 * this first. Pure, zero deps.
 */
const SECRET_KEY_RE =
  /(api[_-]?key|token|secret|password|passwd|credential|authorization|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token)/i;

export function sanitizeText(value: string, maxLength = 2000): string {
  const redacted = value
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/(sk-[A-Za-z0-9]{16,})/g, "[REDACTED_API_KEY]")
    .replace(/(gh[pousr]_[A-Za-z0-9_]{20,})/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/(AKIA[0-9A-Z]{16})/g, "[REDACTED_AWS_KEY]");
  return redacted.length > maxLength ? `${redacted.slice(0, maxLength)}...[truncated]` : redacted;
}

export function redact(value: unknown, depth = 0): unknown {
  if (depth > 5) return "[truncated-depth]";
  if (value == null) return value;
  if (typeof value === "string") return sanitizeText(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redact(item, depth + 1));
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEY_RE.test(key)) {
        out[key] = "[REDACTED]";
      } else if (/^(content|body|fileContent|input|prompt)$/i.test(key) && typeof child === "string") {
        out[key] = sanitizeText(child, 1200);
      } else {
        out[key] = redact(child, depth + 1);
      }
    }
    return out;
  }
  return String(value);
}
