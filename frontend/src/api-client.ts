import type { ApiSchemas } from "./generated/api";

export class ApiFailure extends Error {
  constructor(public readonly status: number, public readonly detail: ApiSchemas["ApiError"]) {
    super(detail.message);
  }
}

export type JobProgressEvent = {
  job_id: string;
  assessment_id: string;
  sequence: number;
  event_id: string;
  kind: string;
  state: string;
  attempt: number;
  created_at: number;
  elapsed_ms: number | null;
  tool_version: string | null;
  exit_code: number | null;
  diagnostic_code: string | null;
  diagnostic: string | null;
};

/** Caller retains the idempotency key across retries. Tokens remain in memory. */
export async function mutate<T>(base: string, path: string, token: string, body: unknown, idempotencyKey: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(base + path, {
    method: "POST", signal,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "X-Request-ID": crypto.randomUUID(), "Idempotency-Key": idempotencyKey },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new ApiFailure(response.status, await response.json() as ApiSchemas["ApiError"]);
  return await response.json() as T;
}

/** Finite SSE batches can reconnect after sleeping hosts using the persisted cursor. */
export async function eventBatch(base: string, assessmentId: string, token: string, cursor: number, signal?: AbortSignal): Promise<{ cursor: number; events: ApiSchemas["AuditEvent"][] }> {
  const response = await fetch(`${base}/api/v1/assessments/${encodeURIComponent(assessmentId)}/events`, {
    signal, headers: { Authorization: `Bearer ${token}`, "Last-Event-ID": String(cursor) },
  });
  if (!response.ok) throw new ApiFailure(response.status, await response.json() as ApiSchemas["ApiError"]);
  const events: ApiSchemas["AuditEvent"][] = [];
  for (const frame of (await response.text()).replace(/\r\n/g, "\n").split("\n\n")) {
    const id = frame.split("\n").find(line => line.startsWith("id: "));
    const data = frame.split("\n").find(line => line.startsWith("data: "));
    if (id && data) {
      const sequence = Number(id.slice(4));
      const event = JSON.parse(data.slice(6)) as ApiSchemas["AuditEvent"];
      if (!Number.isSafeInteger(sequence) || sequence < 1 || event.assessment_id !== assessmentId || !event.event_id) throw new Error("Invalid audit event; reconnect to reconcile history.");
      if (sequence <= cursor) continue;
      cursor = sequence;
      events.push(event);
    }
  }
  return { cursor, events };
}

/** Persisted per-job SSE batches resume from the last fully handled sequence. */
export async function jobEventBatch(base: string, assessmentId: string, jobId: string, token: string, cursor: number, signal?: AbortSignal): Promise<{ cursor: number; events: JobProgressEvent[] }> {
  const response = await fetch(`${base}/api/v1/assessments/${encodeURIComponent(assessmentId)}/scan-jobs/${encodeURIComponent(jobId)}/events`, {
    signal, headers: { Authorization: `Bearer ${token}`, "Last-Event-ID": String(cursor) },
  });
  if (!response.ok) throw new ApiFailure(response.status, await response.json() as ApiSchemas["ApiError"]);
  const events: JobProgressEvent[] = [];
  for (const frame of (await response.text()).replace(/\r\n/g, "\n").split("\n\n")) {
    const id = frame.split("\n").find(line => line.startsWith("id: "));
    const data = frame.split("\n").find(line => line.startsWith("data: "));
    if (id && data) {
      const sequence = Number(id.slice(4));
      const event = JSON.parse(data.slice(6)) as JobProgressEvent;
      if (!Number.isSafeInteger(sequence) || sequence < 1 || event.sequence !== sequence || event.job_id !== jobId || event.assessment_id !== assessmentId) throw new Error("Invalid job event; reconnect to reconcile history.");
      if (sequence <= cursor) continue;
      cursor = sequence;
      events.push(event);
    }
  }
  return { cursor, events };
}
