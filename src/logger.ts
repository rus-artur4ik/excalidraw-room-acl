import { createHash } from "crypto";

type LogFields = Record<string, unknown>;

const redact = (value: string): string =>
  value
    .replace(/Bearer\s+\S+/gi, "Bearer <redacted>")
    .replace(
      /([?&](?:key|token|access_token|id_token)=)[^&\s]+/gi,
      "$1<redacted>",
    );

const errorDetails = (error: unknown, depth = 0): LogFields => {
  if (!(error instanceof Error)) {
    return { value: redact(String(error)) };
  }
  const record = error as Error & Record<string, unknown>;
  const details: LogFields = {
    name: error.name,
    message: redact(error.message),
    stack: error.stack ? redact(error.stack) : undefined,
  };
  for (const key of [
    "code",
    "errno",
    "syscall",
    "path",
    "status",
    "type",
    "description",
  ]) {
    if (record[key] !== undefined) {
      details[key] =
        typeof record[key] === "string"
          ? redact(record[key] as string)
          : record[key];
    }
  }
  if (error.cause !== undefined && depth < 2) {
    details.cause = errorDetails(error.cause, depth + 1);
  }
  return details;
};

const sanitizeValue = (
  value: unknown,
  depth = 0,
  seen = new WeakSet<object>(),
): unknown => {
  if (typeof value === "string") {
    return redact(value);
  }
  if (
    value === null ||
    value === undefined ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (value instanceof Error) {
    return errorDetails(value);
  }
  if (value instanceof Uint8Array) {
    return `<binary:${value.byteLength}>`;
  }
  if (Array.isArray(value)) {
    return depth >= 4
      ? "<max-depth>"
      : value.slice(0, 50).map((item) => sanitizeValue(item, depth + 1, seen));
  }
  if (typeof value === "object") {
    if (seen.has(value)) {
      return "<circular>";
    }
    if (depth >= 4) {
      return "<max-depth>";
    }
    seen.add(value);
    const sanitized: LogFields = {};
    for (const [key, nestedValue] of Object.entries(value).slice(0, 50)) {
      if (
        [
          "authorization",
          "token",
          "idtoken",
          "customtoken",
          "roomkey",
          "apikey",
          "private_key",
        ].includes(key.toLowerCase())
      ) {
        sanitized[key] = "<redacted>";
      } else {
        sanitized[key] = sanitizeValue(nestedValue, depth + 1, seen);
      }
    }
    return sanitized;
  }
  return redact(String(value));
};

const write = (
  level: "info" | "warn" | "error",
  event: string,
  fields: LogFields = {},
): void => {
  const serialized = JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    event,
    ...(sanitizeValue(fields) as LogFields),
  });
  if (level === "error") {
    console.error(serialized);
  } else if (level === "warn") {
    console.warn(serialized);
  } else {
    // eslint-disable-next-line no-console
    console.log(serialized);
  }
};

export const logInfo = (event: string, fields?: LogFields): void =>
  write("info", event, fields);

export const logWarn = (event: string, fields?: LogFields): void =>
  write("warn", event, fields);

export const logError = (
  event: string,
  error: unknown,
  fields: LogFields = {},
): void => write("error", event, { ...fields, error: errorDetails(error) });

export const opaqueRef = (value: string | null | undefined): string =>
  value
    ? createHash("sha256").update(value).digest("hex").slice(0, 12)
    : "anonymous";
