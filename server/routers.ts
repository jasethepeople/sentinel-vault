import { COOKIE_NAME } from "@shared/const";
import { parse as parseCookie } from "cookie";
import { z } from "zod";
import { getSessionCookieOptions } from "./_core/cookies";
import { createHeartbeatJob, deleteHeartbeatJob, updateHeartbeatJob } from "./_core/heartbeat";
import { ENV } from "./_core/env";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import {
  configureSentinel,
  deleteVaultEntry,
  getSentinelOverview,
  panicWipeVault,
  recordCheckIn,
  saveScheduleReference,
  storeVaultEntry,
} from "./sentinelDb";

const scheduleCron = "0 */5 * * * *";
const graceInput = z.object({
  checkInIntervalMinutes: z.number().int().min(5).max(525600),
  alertGraceMinutes: z.number().int().min(1).max(525600),
  criticalGraceMinutes: z.number().int().min(1).max(525600),
});

function sessionToken(cookieHeader: string | undefined) {
  return parseCookie(cookieHeader ?? "")[COOKIE_NAME] ?? "";
}

export const appRouter = router({
    // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),
  sentinel: router({
    overview: protectedProcedure.query(({ ctx }) => getSentinelOverview(ctx.user.id)),
    createVault: protectedProcedure.input(z.object({
      ciphertext: z.string().min(1).max(8_000_000),
      iv: z.string().min(8).max(128),
      encryptionVersion: z.literal("AES-GCM-256/v1"),
    })).mutation(async ({ ctx, input }) => ({ id: await storeVaultEntry(ctx.user.id, input) })),
    deleteVault: protectedProcedure.input(z.object({ id: z.string().min(8).max(32) })).mutation(async ({ ctx, input }) => {
      await deleteVaultEntry(ctx.user.id, input.id);
      return { ok: true };
    }),
    configure: protectedProcedure.input(graceInput).mutation(async ({ ctx, input }) => {
      const profile = await configureSentinel(ctx.user.id, input);
      // A callback must point to a published service. Development saves the desired policy but deliberately does not register a live job.
      if (!ENV.isProduction) return { profile, scheduler: "PENDING_PUBLICATION" as const };
      const token = sessionToken(ctx.req.headers.cookie);
      if (profile.scheduleCronTaskUid) {
        const job = await updateHeartbeatJob(profile.scheduleCronTaskUid, {
          cron: scheduleCron, path: "/api/scheduled/sentinel-heartbeat", description: "Sentinel liveness and escalation evaluator",
        }, token);
        await saveScheduleReference(ctx.user.id, profile.scheduleCronTaskUid, job.nextExecutionAt ? new Date(job.nextExecutionAt) : null);
      } else {
        const job = await createHeartbeatJob({
          name: `sentinel-heartbeat-${ctx.user.id}`,
          cron: scheduleCron,
          path: "/api/scheduled/sentinel-heartbeat",
          description: "Sentinel liveness and escalation evaluator",
        }, token);
        await saveScheduleReference(ctx.user.id, job.taskUid, job.nextExecutionAt ? new Date(job.nextExecutionAt) : null);
      }
      return { profile: await getSentinelOverview(ctx.user.id).then(result => result.profile), scheduler: "ARMED" as const };
    }),
    checkIn: protectedProcedure.mutation(async ({ ctx }) => {
      await recordCheckIn(ctx.user.id);
      return { ok: true };
    }),
    panicWipe: protectedProcedure.input(z.object({ confirmation: z.literal("WIPE") })).mutation(async ({ ctx, input }) => {
      const taskUid = await panicWipeVault(ctx.user.id);
      if (taskUid && ENV.isProduction) {
        try { await deleteHeartbeatJob(taskUid, sessionToken(ctx.req.headers.cookie)); } catch (error) { console.error("[Sentinel wipe] Could not remove scheduled job", error); }
      }
      return { ok: true, confirmation: input.confirmation };
    }),
  }),
});

export type AppRouter = typeof appRouter;
