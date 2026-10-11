/**
 * Output hygiene shared by every milestone. Everything the extension prints, logs or stores in
 * the architecture model must pass through these helpers when it originates from the scanned
 * project (file contents, error text, names) or from the local machine (absolute paths).
 */

/** First line only; absolute paths replaced by "<path>". Never echoes more than the error's own wording. */
export function sanitizeErrorMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  return redactAbsolutePaths(raw.split(/\r?\n/, 1)[0].trim());
}

// A character that can continue a path token: not whitespace, quote, backtick, comma, semicolon or ")".
const FILE_URL = /\bfile:\/\/\/[^\s'"`,;)]+/gi;
// Drive letter must start a token (so the "s:/" in "https://" never matches). Backslash form: any tail.
// Forward-slash form needs two segments (C:/Users/x), so prose such as "a:/b" is kept.
const WINDOWS_DRIVE = /(?<![A-Za-z0-9_])[A-Za-z]:(?:\\[^\s'"`,;)]*|\/[^\s'"`,;)/\\]+\/[^\s'"`,;)]*)/g;
// A QUOTED absolute path is redacted up to its closing quote, so directories containing spaces
// ("/Users/Bob Smith/My Project/x", "C:\\Users\\Bob Smith\\p") do not leak their tail. Node quotes paths in fs errors.
const QUOTED_PATH = /(['"])(?:\/(?=[\w.~@])|[A-Za-z]:(?:\\|\/[^'"/\\]+\/)|\\\\[\w.$-]+\\)(?:(?!\1)[^\r\n])*\1/g;
const UNC = /(?<![\\\w])\\\\[\w.$-]+\\[^\s'"`,;)]+/g;
// A token starting with "/" followed by a NAME character. '/', '/*', '//', "//comment" and "and/or" are not paths.
const POSIX = /(^|[\s'"(=])\/(?=[\w.~@])[^\s'"`,;)]*/g;

/**
 * Replace absolute local paths with "<path>" while leaving ordinary text alone.
 *  file URLs  file:///home/x/p, file:///C:/x        -> file://<path>
 *  Windows    C:\Users\x\p, c:\x, C:/Users/x/p
 *  UNC        \\server\share\file
 *  POSIX      /home/x/p, '/package.json', path=/var/tmp
 * Relative paths, URLs ("https://host/x"), and quoted punctuation such as '/' or '/*' are never changed.
 * Known limit: an UNQUOTED path containing spaces is redacted only up to its first space.
 */
export function redactAbsolutePaths(text: string): string {
  return text
    .replace(FILE_URL, 'file://<path>')
    .replace(QUOTED_PATH, '$1<path>$1')
    .replace(WINDOWS_DRIVE, '<path>')
    .replace(UNC, '<path>')
    .replace(POSIX, '$1<path>');
}

/**
 * Remove credentials from URL-style specifiers ("https://user:pass@host", "https://TOKEN@host")
 * (the userinfo becomes "***") and registry-style image references ("user:pass@registry.io/app", where the
 * credentials are removed entirely). The conventional SSH user
 * "git@" is not a credential and is kept, so ordinary git URLs stay exact. Tag+digest image
 * references ("node:20@sha256:...") are not touched.
 */
export function redactCredentials(text: string): string {
  return text
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)([^/\s@]+)@/gi, (match, scheme: string, userinfo: string) =>
      userinfo === 'git' ? match : `${scheme}***@`
    )
    .replace(/[^/\s:@]+:[^/\s@]+@(?=[^/\s@]+\/)/g, ''); // removed outright: a leftover "@" would be read as a digest separator
}

/** Replace control characters so untrusted names cannot inject extra lines or escape sequences into output. */
export function stripControlCharacters(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ');
}
