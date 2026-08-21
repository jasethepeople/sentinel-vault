import type { Request, Response } from "express";
import { sdk } from "./_core/sdk";
import { advanceEscalationForTask } from "./sentinelDb";

/** HTTP-cron endpoint. It relies only on the authenticated scheduler task UID, never request-body values. */
export async function evaluateSentinelHeartbeat(req: Request, res: Response) {
  try {
    const user = await sdk.authenticateRequest(req);
    if (!user.isCron || !user.taskUid) return res.status(403).json({ error: "cron-only" });
    const result = await advanceEscalationForTask(user.taskUid);
    return res.json({ ok: true, result });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[Sentinel heartbeat]", message);
    return res.status(500).json({ error: message, context: { url: req.originalUrl }, timestamp: new Date().toISOString() });
  }
}
