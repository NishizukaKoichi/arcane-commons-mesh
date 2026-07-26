import { createApp } from "./app";
import { runMaintenance } from "./maintenance";

const { app } = createApp();

export default {
  fetch: app.fetch,
  async scheduled(
    controller: ScheduledController,
    env: { DB: D1Database },
    context: ExecutionContext
  ): Promise<void> {
    context.waitUntil(runMaintenance(env.DB, Math.floor(controller.scheduledTime / 1000)));
  }
};
