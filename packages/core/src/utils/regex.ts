/**
 * Regex safety utilities — ReDoS complexity validation
 *
 * Detects known ReDoS-prone patterns in user-supplied regular expressions:
 * - Nested quantifiers: (a+)+, (a*)*
 * - Overlapping alternations with quantifiers: (a|a)+
 * - Star-height > 1 patterns
 */

/**
 * Check if a regex pattern is likely safe from ReDoS.
 * Returns true if the pattern appears safe, false if it contains
 * suspicious nested quantifier patterns.
 *
 * This is a heuristic check — not a formal proof — but catches
 * the most common ReDoS-prone constructs.
 */
export function isRedosSafe(pattern: string): boolean {
  // Reject patterns longer than 512 chars (overly complex)
  if (pattern.length > 512) return false;

  // Detect nested quantifiers: (...)+ followed by +, *, {n,}
  // e.g., (a+)+, (a*)+, (a+)*, (a{2,})+
  if (/\([^)]*[+*][^)]*\)[+*{]/.test(pattern)) return false;

  // Detect (.+)+ or (.*)+  patterns (common ReDoS)
  if (/\(\.\*\)[+*]/.test(pattern)) return false;
  if (/\(\.\+\)[+*]/.test(pattern)) return false;

  // Detect alternation with quantifiers that can overlap: (a|a)+
  // Simplified: group with | inside, followed by quantifier
  // This is a very rough heuristic
  if (/\([^)]*\|[^)]*\)[+*]{1,2}/.test(pattern)) {
    // Further check: only flag if the alternation branches share common prefixes
    // For simplicity, we flag any alternation with quantifier on the group
    return false;
  }

  return true;
}
