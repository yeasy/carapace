import { DashboardServer } from "@carapace/dashboard";
import { color, COLORS, parsePort } from "../utils.js";

export async function dashboardCommand(flags: Record<string, string | boolean> = {}): Promise<void> {
  const port = parsePort(flags.port, 9877);
  const host = typeof flags.host === "string" ? flags.host : "127.0.0.1";

  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost") {
    console.warn(`\n  ${color("WARNING:", COLORS.yellow)} Binding to ${host} exposes the unauthenticated dashboard to the network.`);
  }

  console.log(`\n${color("Carapace Dashboard", COLORS.bright)}\n`);

  const server = new DashboardServer({ port, host });
  try {
    await server.start();
  } catch (err: unknown) {
    if (err instanceof Error && (err as NodeJS.ErrnoException).code === "EADDRINUSE") {
      console.error(`\n  ${color("✖", COLORS.red)} Port ${port} is already in use. Try ${color(`--port ${port + 1}`, COLORS.cyan)}\n`);
      process.exitCode = 1;
      return;
    }
    throw err;
  }

  const displayHost = host.includes(":") ? `[${host}]` : host;
  console.log(`  ${color("●", COLORS.green)} Dashboard running at ${color(`http://${displayHost}:${port}/dashboard`, COLORS.cyan)}`);
  console.log(`  ${color("●", COLORS.green)} API available at ${color(`http://${displayHost}:${port}/api`, COLORS.cyan)}`);
  console.log(`\n  Press ${color("Ctrl+C", COLORS.yellow)} to stop\n`);

  // Try to open browser (use execFile to avoid shell injection)
  try {
    const { execFile } = await import("node:child_process");
    const url = `http://${displayHost}:${port}/dashboard`;
    const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
    const args = process.platform === "win32" ? ["/c", "start", url] : [url];
    execFile(cmd, args, () => {/* ignore errors */});
  } catch {
    // Silently ignore if browser can't be opened
  }

  // Keep alive until Ctrl+C or SIGTERM
  await new Promise<void>((resolve) => {
    const shutdown = async () => {
      process.removeListener("SIGINT", shutdown);
      process.removeListener("SIGTERM", shutdown);
      console.log(`\n  ${color("Shutting down...", COLORS.yellow)}`);
      try { await server.stop(); } catch {}
      resolve();
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });
}
