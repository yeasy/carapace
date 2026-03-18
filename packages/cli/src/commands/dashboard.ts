import { DashboardServer } from "@carapace/dashboard";
import { color, COLORS, loadConfig, getDbPath } from "../utils.js";

export async function dashboardCommand(flags: Record<string, string | boolean> = {}): Promise<void> {
  const config = loadConfig();
  const port = typeof flags.port === "string" ? parseInt(flags.port, 10) : 9877;
  const host = typeof flags.host === "string" ? flags.host : "0.0.0.0";

  console.log(`\n${color("Carapace Dashboard", COLORS.bright)}\n`);

  const server = new DashboardServer({ port, host });
  await server.start();

  console.log(`  ${color("●", COLORS.green)} Dashboard running at ${color(`http://localhost:${port}/dashboard`, COLORS.cyan)}`);
  console.log(`  ${color("●", COLORS.green)} API available at ${color(`http://localhost:${port}/api`, COLORS.cyan)}`);
  console.log(`\n  Press ${color("Ctrl+C", COLORS.yellow)} to stop\n`);

  // Try to open browser
  try {
    const { exec } = await import("node:child_process");
    const url = `http://localhost:${port}/dashboard`;
    const cmd = process.platform === "darwin" ? `open ${url}` : process.platform === "win32" ? `start ${url}` : `xdg-open ${url}`;
    exec(cmd);
  } catch {
    // Silently ignore if browser can't be opened
  }

  // Keep alive until Ctrl+C
  await new Promise<void>((resolve) => {
    process.on("SIGINT", async () => {
      console.log(`\n  ${color("Shutting down...", COLORS.yellow)}`);
      await server.stop();
      resolve();
    });
  });
}
