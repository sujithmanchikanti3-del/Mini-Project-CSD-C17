import { sanitizeErrorMessage } from '../../../common/sanitize';

/** Small helpers shared by the manifest parsers. */

export function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** First line only, so error text from third-party parsers can never echo file content. */
export function firstLine(message: string): string {
  return message.split(/\r?\n/, 1)[0].trim();
}

export function describeError(error: unknown): string {
  return sanitizeErrorMessage(error); // first line only, absolute paths redacted
}
