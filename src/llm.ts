// The model provider: Meterless Nightshift's local runtime (OpenAI-compatible). Nightshift routes the request;
// with an NVIDIA key configured it serves Nemotron. Follows the Meterless provider contract: real bearer token,
// meterless-app on every request, meterless-scope: user on chat, 180 s timeout, honest offline/unauthorized states.

import { need } from "./config.ts";

export type ProviderState = { state: "online"; models: string[] } | { state: "unauthorized" } | { state: "offline"; reason: string };

export interface ChatTurn {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ChatResult {
  content: string;
  model: string;
  ms: number;
  usage?: { prompt_tokens?: number; completion_tokens?: number };
}

export const APP_ID = "receipts";

export function normaliseBaseUrl(raw: string): string {
  let u = raw.trim();
  if (!/^https?:\/\//.test(u)) u = "http://" + u;
  const url = new URL(u);
  return `${url.protocol}//${url.host}/v1`;
}

export class Nightshift {
  readonly base = normaliseBaseUrl(process.env.METERLESS_BASE_URL ?? "http://127.0.0.1:8088/v1");
  private readonly token = need("METERLESS_RUNTIME_TOKEN");
  readonly model = process.env.METERLESS_MODEL ?? "meterless/auto";
  readonly calls: { model_requested: string; model_served: string; ms: number; usage?: ChatResult["usage"] }[] = [];

  private headers(chat: boolean): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
      "meterless-app": APP_ID,
      ...(chat ? { "meterless-scope": "user", "Content-Type": "application/json" } : {}),
    };
  }

  async status(): Promise<ProviderState> {
    try {
      const r = await fetch(`${this.base}/models`, { headers: this.headers(false), signal: AbortSignal.timeout(10_000) });
      if (r.status === 401 || r.status === 403) return { state: "unauthorized" };
      if (r.status !== 200) return { state: "offline", reason: `GET /v1/models -> ${r.status}` };
      const j = (await r.json()) as { data?: { id: string }[] };
      const models = (j.data ?? []).map((m) => m.id);
      return models.some((m) => m.startsWith("meterless/")) ? { state: "online", models } : { state: "offline", reason: "no meterless/* models listed" };
    } catch (e) {
      return { state: "offline", reason: (e as Error).message };
    }
  }

  async chat(messages: ChatTurn[], opts: { temperature?: number; max_tokens?: number } = {}): Promise<ChatResult> {
    const t0 = Date.now();
    const r = await fetch(`${this.base}/chat/completions`, {
      method: "POST",
      headers: this.headers(true),
      body: JSON.stringify({ model: this.model, messages, temperature: opts.temperature ?? 0.1, max_tokens: opts.max_tokens ?? 4096 }),
      signal: AbortSignal.timeout(180_000),
    });
    const text = await r.text();
    if (r.status !== 200) throw new Error(`Nightshift chat -> ${r.status} ${text.slice(0, 200)}`);
    const j = JSON.parse(text) as { model?: string; choices?: { message?: { content?: string } }[]; usage?: ChatResult["usage"] };
    const res: ChatResult = { content: j.choices?.[0]?.message?.content ?? "", model: j.model ?? this.model, ms: Date.now() - t0, usage: j.usage };
    this.calls.push({ model_requested: this.model, model_served: res.model, ms: res.ms, usage: res.usage });
    return res;
  }
}

/** Pull the first JSON object out of a model reply (tolerates code fences and prose around it). */
export function extractJson(text: string): unknown {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const body = fenced ? fenced[1] : text;
  const start = body.indexOf("{");
  if (start < 0) throw new Error("no JSON object in the model reply");
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < body.length; i++) {
    const c = body[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
    } else if (c === '"') inStr = true;
    else if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return JSON.parse(body.slice(start, i + 1));
  }
  throw new Error("unterminated JSON object in the model reply");
}
