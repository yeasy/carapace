/**
 * Extracts string content from an MCP-style tool result.
 *
 * Handles both plain string results and structured `{ content: [{ text }] }` shapes
 * commonly returned by MCP tool calls.
 */
export function extractStringContent(result: unknown): string | null {
  if (typeof result === "string") return result;
  if (typeof result === "object" && result !== null && "content" in result) {
    const obj = result as { content: unknown };
    if (Array.isArray(obj.content)) {
      const texts: string[] = [];
      for (const item of obj.content) {
        if (typeof item === "object" && item !== null && "text" in item) {
          const val = (item as { text: unknown }).text;
          if (typeof val === "string") texts.push(val);
        }
      }
      return texts.length > 0 ? texts.join("\n") : null;
    }
  }
  return null;
}
