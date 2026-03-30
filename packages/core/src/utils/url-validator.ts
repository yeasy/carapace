/**
 * SSRF protection — validate URLs against private/loopback IP patterns.
 */

/** Private/loopback IP patterns for SSRF validation */
export const PRIVATE_IP_PATTERNS = [
  /^127\./,                           // IPv4 loopback
  /^10\./,                            // RFC 1918
  /^172\.(1[6-9]|2\d|3[01])\./,       // RFC 1918
  /^192\.168\./,                       // RFC 1918
  /^169\.254\./,                       // link-local
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // CGNAT (RFC 6598)
  /^0\./,                             // current network
  /^::1$/,                            // IPv6 loopback
  /^::$/,                             // IPv6 all-zeros
  /^fc[0-9a-f]{0,2}:/i,               // IPv6 unique local (require colon to avoid matching domain names)
  /^fd[0-9a-f]{0,2}:/i,               // IPv6 unique local (require colon to avoid matching domain names)
  /^fe80:/i,                           // IPv6 link-local (require colon to avoid matching domain names)
  /^::ffff:/i,                        // IPv4-mapped IPv6 (short form)
  /^0{0,4}:0{0,4}:0{0,4}:0{0,4}:0{0,4}:ffff:/i, // IPv4-mapped IPv6 (full form)
  /^localhost$/i,
  /^0x[0-9a-f]+$/i,                   // hex-encoded IP (e.g. 0x7f000001)
  /(?:^|\.)(0x[0-9a-f]+)(?:\.|$)/i,   // dotted-hex IP (e.g. 0x7f.0.0.1)
  /(?:^|\.)(0\d+)(?:\.|$)/,           // dotted-octal IP (e.g. 0177.0.0.1 with mixed segments)
  /^\d{8,10}$/,                       // decimal IP (e.g. 2130706433)
  /^0[0-7]{1,3}\./,                   // octal-encoded IP (e.g. 0177.0.0.1)
  /\.nip\.io$/i,                      // wildcard DNS services
  /\.sslip\.io$/i,                    // wildcard DNS services
  /\.xip\.io$/i,                      // wildcard DNS services
  /\blocaltest\.me$/i,                // resolves to 127.0.0.1
  /\blvh\.me$/i,                      // resolves to 127.0.0.1
  /\bvcap\.me$/i,                     // resolves to 127.0.0.1
  /\btraefik\.me$/i,                  // resolves to 127.0.0.1
];

/**
 * Validate a URL is safe for outbound requests (no private/loopback IPs).
 * Throws on invalid or dangerous URLs.
 *
 * @param url  - The URL string to validate
 * @param label - A label used in error messages (e.g. "WebhookSink", "SplunkSink")
 * @returns The parsed URL object
 */
export function validatePublicUrl(url: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${label}: invalid URL "${url}"`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`${label} only supports http/https URLs, got: ${parsed.protocol}`);
  }
  // Block private/loopback IPs to prevent SSRF
  const host = parsed.hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  for (const pat of PRIVATE_IP_PATTERNS) {
    if (pat.test(host)) {
      throw new Error(`${label}: private/loopback addresses not allowed: ${host}`);
    }
  }
  return parsed;
}
