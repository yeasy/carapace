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

  // Reject backreference patterns (\1, \2, etc.) which can cause catastrophic backtracking
  if (/\\[1-9]/.test(pattern)) return false;

  // Detect nested quantifiers: (...)+ followed by +, *, {n,}
  // e.g., (a+)+, (a*)+, (a+)*, (a{2,})+, (a{2,}){2,}
  if (/\([^)]*(?:[+*]|\{\d+,\d*\})[^)]*\)[+*{]/.test(pattern)) return false;

  // Detect nested groups with inner quantifiers: ((a+))+ or ((a+)(b+))+
  // The outer group has a quantifier and contains an inner group with a quantifier
  if (/\((?:[^()]*\([^()]*[+*][^()]*\))+[^()]*\)[+*{]/.test(pattern)) return false;

  // Detect (.+)+ or (.*)+  patterns (common ReDoS)
  if (/\(\.\*\)[+*]/.test(pattern)) return false;
  if (/\(\.\+\)[+*]/.test(pattern)) return false;

  // Detect alternation with quantifiers that can overlap: (a|a)+
  // Simplified: group with | inside, followed by quantifier
  // This is a very rough heuristic
  if (/\([^)]*\|[^)]*\)[+*]{1,2}/.test(pattern)) {
    // Extract alternation groups with quantifiers and check for overlapping branches
    const groupRe = /\(([^)]*\|[^)]*)\)[+*]{1,2}/g;
    let m: RegExpExecArray | null;
    while ((m = groupRe.exec(pattern)) !== null) {
      const branches = m[1].split("|");
      // Safe if all branches are literal strings (no regex metacharacters)
      const allLiteral = branches.every((b) => /^[a-zA-Z0-9_-]+$/.test(b));
      if (allLiteral) {
        // Check for duplicate or prefix-overlapping branches which cause ReDoS
        const unique = new Set(branches);
        if (unique.size < branches.length) return false; // exact duplicates
        for (let i = 0; i < branches.length; i++) {
          for (let j = 0; j < branches.length; j++) {
            if (i !== j && branches[j].startsWith(branches[i])) return false;
          }
        }
        continue;
      }
      // Unsafe: branches contain metacharacters and could overlap
      return false;
    }
  }

  return true;
}
