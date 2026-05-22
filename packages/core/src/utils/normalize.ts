/**
 * Shared Unicode normalization utilities.
 *
 * INVISIBLE_CHARS_RE strips invisible / zero-width Unicode characters that
 * can be injected to evade pattern-matching rules.  The same regex was
 * previously duplicated across exec-guard, path-guard, data-exfil,
 * prompt-injection, baseline, and yaml-rule â it now lives here once.
 */

export const INVISIBLE_CHARS_RE = /[\u00AD\u115F\u1160\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2069\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB]|\uDB40[\uDC01-\uDC7F]/g;
