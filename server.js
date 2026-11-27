const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const OpenAI = require("openai");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto"); // Phase 0: only used for optional Supabase JWT checks — no new dependency.
dotenv.config();

const app = express();
app.set("trust proxy", 1); /* Batch 9: Render forwards X-Forwarded-For - trust one proxy hop so express-rate-limit keys by the real user IP, not the proxy IP (was: every user shared one rate-limit bucket, plus ERR_ERL_UNEXPECTED_X_FORWARDED_FOR warnings). */

const analyzeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many requests. Please try again later." },
});
app.use(cors({
  origin: ["https://beforeyousay.com", "http://localhost:3000"],
  methods: ["GET", "POST"],
}));
/* ---------- Batch 8 Pro checkout: Stripe webhook ----------
   Stripe posts payment events here. This route is registered BEFORE
   express.json on purpose: the signature check needs the exact raw
   body Stripe sent, and a JSON parser would change it. express.raw
   hands us a Buffer; verifyStripeSignature (below) checks the
   stripe-signature header against STRIPE_WEBHOOK_SECRET. A bad
   signature, a stale timestamp, or a missing secret is refused —
   nobody can fake a payment by posting to this URL. */
app.post("/stripe-webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return res.status(503).send("Webhook is not set up on the server yet.");
  const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || "");
  if (!verifyStripeSignature(raw, req.headers["stripe-signature"] || "", secret)) {
    return res.status(400).send("Bad signature.");
  }
  let event;
  try { event = JSON.parse(raw.toString("utf8")); } catch (e) { return res.status(400).send("Bad payload."); }
  const change = planFromStripeEvent(event);
  if (!change) return res.json({ received: true, ignored: true }); /* event type we do not act on */
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(503).send("Plan storage is not set up on the server yet.");
  }
  /* Batch 11: the change now carries the Stripe customer/subscription ids and the period end, so the profile row knows which subscription to cancel later. Fields set to undefined are left alone; null clears a column (see supabaseAdminUpsertProfileFields). */
  const fields = { plan: change.plan };
  if (change.stripeCustomerId !== undefined) fields.stripe_customer_id = change.stripeCustomerId;
  if (change.stripeSubscriptionId !== undefined) fields.stripe_subscription_id = change.stripeSubscriptionId;
  if (change.planEndsAt !== undefined) fields.plan_ends_at = change.planEndsAt;
  const saved = await supabaseAdminUpsertProfileFields(change.userId, fields);
  if (!saved) return res.status(500).send("Could not save the plan change."); /* Stripe retries */
  return res.json({ received: true, plan: change.plan });
});

/* Sprint 2: screenshot threads send Base64 images, so /analyze-thread
   gets a 10mb JSON body limit; every other route stays at 1mb. The
   thread handler also checks the decoded image total itself (see
   sanitiseThreadImages) and answers 413 when it is too large. */
app.use(function (req, res, next) {
  if (req.path === "/analyze-thread") return express.json({ limit: "10mb" })(req, res, next);
  if (req.path === "/vault/upload" || req.path === "/hr-audit") return express.json({ limit: "14mb" })(req, res, next);
  return express.json({ limit: "1mb" })(req, res, next);
});

/* Sprint 2 fix pass: a body over the parser limit (10mb on
   /analyze-thread, 1mb elsewhere) gets a friendly JSON 413, never
   Express's default HTML error page and never a crash. */
app.use(function (err, req, res, next) {
  if (err && (err.type === "entity.too.large" || err.status === 413)) {
    const msg = req.path === "/analyze-thread"
      ? "That upload is too large — try fewer or smaller screenshots."
      : (req.path === "/vault/upload" || req.path === "/hr-audit")
      ? "That file is too large — 10MB max per document."
      : "That message is too large. Please keep it under 1000 characters.";
    return res.status(413).json({ error: msg });
  }
  return next(err);
});

app.get("/", (req, res) => {
  res.send("BeforeYouSay backend is live");
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "BeforeYouSay backend",
    time: new Date().toISOString(),
  });
});

/* Sprint 2 fix pass: the client is null when no OpenAI key is set, so the
   server still starts when Gemini or MOCK_AI serves the vision route.
   /analyze still gates on the key before using the client, and the
   /analyze-thread OpenAI branch gates on the client below. */
const client = process.env.OPENAI_API_KEY
  ? new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
      timeout: 60000, /* Batch 4: a hung AI call fails after 60s instead of hanging forever */
    })
  : null;

/* ---------- Phase 0: optional Supabase sign-in (backwards compatible) ----------
   - If no Authorization header is sent, or SUPABASE_JWT_SECRET is not set,
     this does nothing and the site works exactly as today (anonymous).
   - If a Bearer token IS sent and SUPABASE_JWT_SECRET IS set, we check the
     token is a real Supabase JWT signed with that secret (HS256). A bad or
     expired token is ignored — the request still runs anonymously.
   - Nothing in the /analyze response changes. req.authUser is only used
     later, when cloud history is switched on. No token is ever logged.
   - Note: newer Supabase projects sign tokens with ES256 / JWKS instead of
     HS256. If yours does, leave SUPABASE_JWT_SECRET unset for now — Phase 0
     still works — and add JWKS checking in Phase 1. */
function sanitiseToneProfile(input) {
  if (!input || typeof input !== "object") return null;
  const clean = (v) => (typeof v === "string" ? v.trim().slice(0, 80) : "");
  const num = (v) => { const n = Number(v); return Number.isFinite(n) ? Math.min(5, Math.max(1, Math.round(n))) : 3; };
  const mode = ["career", "negotiation", "high_conflict", "boundaries"].includes(input.defaultMode) ? input.defaultMode : null;
  const reply = ["balanced", "calm", "assertive", "warm"].includes(input.defaultReplyStyle) ? input.defaultReplyStyle : null;
  return { name: clean(input.name), directness: num(input.directness), warmth: num(input.warmth), formality: num(input.formality), playfulness: num(input.playfulness), defaultMode: mode, defaultReplyStyle: reply };
}
function toneProfileText(p) {
  if (!p) return "";
  const bits = [];
  if (p.name) bits.push(`The user is called ${p.name}.`);
  bits.push(`Saved tone (1 = low, 5 = high): directness ${p.directness}/5, warmth ${p.warmth}/5, formality ${p.formality}/5, playfulness ${p.playfulness}/5.`);
  if (p.defaultReplyStyle) bits.push(`Usual reply style: ${p.defaultReplyStyle}.`);
  return "\nUser's saved tone profile:\n" + bits.join(" ") + "\nMatch the rewrites to that tone, without changing the mode's job.";
}
/* ---------- Phase 1 contexts+styles: optional style + saved person ---------- */
function sanitiseStyle(input) {
  return ["shorter", "warmer", "firmer", "funnier"].includes(input) ? input : null;
}
function sanitiseContext(input) {
  if (!input || typeof input !== "object") return null;
  const name = typeof input.name === "string" ? input.name.trim().slice(0, 50) : "";
  if (!name) return null;
  const note = typeof input.note === "string" ? input.note.trim().slice(0, 200) : "";
  return { name, note };
}
function contextText(c) {
  if (!c) return "";
  const note = c.note ? ` How the user wants to sound with them: ${c.note}.` : "";
  return `\nThis message is for ${c.name}.${note} Adapt the rewrites to that relationship — the same words land differently with different people — without changing the mode's job.`;
}
function styleText(style) {
  const styles = {
    shorter: "\nRewrite style requested: SHORTER. Make better_version noticeably shorter and tighter than the original — cut filler, keep the meaning and the tone. Keep the other versions short too.",
    warmer: "\nRewrite style requested: WARMER. Make better_version warmer and kinder, with more care in the wording, without sounding fake or over-the-top.",
    firmer: "\nRewrite style requested: FIRMER. Make better_version firmer, more direct and more confident, without sounding rude or aggressive.",
    funnier: "\nRewrite style requested: FUNNIER. Make better_version funnier and more playful, keeping it natural — never cringe, try-hard, or mean.",
  };
  return styles[style] || "";
}
function sanitiseGoal(input) {
  if (typeof input !== "string") return null;
  const goal = input.trim().slice(0, 200);
  return goal ? goal : null;
}
function sanitiseDraft(input) {
  if (typeof input !== "string") return null;
  const draft = input.trim().slice(0, 1000);
  return draft ? draft : null;
}
function goalText(goal) {
  if (!goal) return "";
  return "\nUser's exact goal: " + goal + "\nJudge every version against that goal — the best version is the one most likely to achieve it.";
}
function draftText(draft) {
  if (!draft) return "";
  return "\nThe user already drafted a reply. Grade it in draft_critique and fix it in your versions — do not just repeat it:\n" + draft;
}
function base64UrlDecode(s) { return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64"); }
function verifySupabaseJwt(token) {
  const secret = process.env.SUPABASE_JWT_SECRET;
  if (!secret) return null;
  const parts = String(token).split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(base64UrlDecode(parts[0]).toString("utf8"));
    if (header.alg !== "HS256") return null; // ES256/JWKS tokens are left for Phase 1
    const expected = crypto.createHmac("sha256", secret).update(parts[0] + "." + parts[1]).digest();
    const actual = base64UrlDecode(parts[2]);
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return null;
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString("utf8"));
    if (payload.exp && payload.exp * 1000 < Date.now()) return null;
    return { id: payload.sub || null, email: payload.email || null };
  } catch (e) { return null; }
}
function optionalAuth(req, res, next) {
  req.authUser = null;
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return next();
  req.authUser = verifySupabaseJwt(h.slice(7).trim());
  return next();
}

function buildSystemPrompt(mode, toneProfile, style, context, goal, draft) {
  const commonRules = `
You are BeforeYouSay, an elite AI communication coach.

Your job is NOT to act like a generic chatbot.
Your job is to help users rewrite, analyze, and emotionally optimize messages before sending them.

Always be:
- emotionally intelligent
- socially aware
- clear
- practical
- modern
- non-cringe
- calm
- specific

Do not sound robotic.
Do not sound overly therapist-like.
Do not overexplain.
Do not use emojis.
Do not use quotation marks around rewrite suggestions unless needed.

Keep the user's own words and phrasing wherever they already work — only change what needs changing. A rewrite that sounds like a different person is a bad rewrite, even if the grammar is perfect.

Return valid JSON only.
`;

  const outputFormat = `
Return this exact JSON structure:

{
  "mode": "string",
  "original_message": "string",
  "tone_detected": "string",
  "intent_guess": "string",
  "risk_level": "low | medium | high",
  "should_send": "yes | edit_first | no",
  "why_it_might_land_badly": "string",
  "better_version": "string",
  "softer_version": "string",
  "stronger_version": "string",
  "coach_note": "string",
  "power_dynamic": "string",
  "emotional_trap": "string",
  "draft_critique": "object or null",
  "replies": [
    { "strategy": "Hold the Line (Firm)", "message": "string", "why_it_works": "string" },
    { "strategy": "De-escalate (Neutral)", "message": "string", "why_it_works": "string" },
    { "strategy": "Strategic Pivot (Reframe)", "message": "string", "why_it_works": "string" }
  ],
  "scores": {
    "clarity": 0,
    "confidence": 0,
    "emotional_control": 0,
    "effectiveness": 0
  }
}

Rules:
- Scores must be integers from 1 to 10.
- better_version must be the best final version for the chosen mode.
- softer_version should feel gentler.
- stronger_version should feel more direct/confident.
- coach_note should be short and useful: name the single riskiest phrase in the original message and give one concrete fix for it — never generic advice like "be clearer".
- why_it_might_land_badly should explain how the message may be perceived, quoting the exact words that could land badly.
- If the message is already strong, still improve it slightly.
- Scores must match the text you just wrote: if the original is already clear and low-risk, scores are 8-10; if it is confusing or likely to upset the reader, effectiveness and emotional_control are 5 or below. Never give all four scores the same number.
- power_dynamic must be exactly 2 sentences: who has the leverage in this exchange, and what tactic the other person is using (for example guilt-tripping, false urgency, or moving the goalposts).
- emotional_trap must be exactly 1 sentence: what happens if the user replies defensively.
- draft_critique is null when no draft was provided. When a draft was provided, it is {"score": 0-100, "flaw": "the exact flaw in 1 sentence"} — score how well the draft serves the user's goal.
- replies must be exactly 3, in this order, with these exact strategy labels: "Hold the Line (Firm)", "De-escalate (Neutral)", "Strategic Pivot (Reframe)". Each message is the exact copy-pasteable text the user can send; each why_it_works is 1 line.
`;

  const modeGuidance = {
    career: `
Mode: Career & Boss
Optimize for pushback, raises, boundary setting, and covering yourself for HR. Document facts, stay professional, and keep a paper trail in the wording.
Avoid sounding emotional, passive-aggressive, or apologetic about reasonable boundaries.
`,
    negotiation: `
Mode: Client & Negotiation
Optimize for scope creep, pricing pushback, and closing deals. Be firm on value, name clear terms, and never concede without getting something back.
Avoid sounding needy, overexplaining, or defensive.
`,
    high_conflict: `
Mode: High-Conflict / Legal & Co-Parenting — STRICT BIFF
BIFF only: Brief, Informative, Friendly, Firm. Keep every version short and factual. State only what happened, what you need, or what will happen next.
No emotional hooks, no blame, no sarcasm, no advice about the other person, no rehashing history.
`,
    boundaries: `
Mode: Hard Personal Boundaries
Optimize for saying no to family and friends without blowing up the relationship. Warm but firm: one clear no, no over-explaining, no justifying, no apologising for the boundary itself.
Avoid sounding cold, guilty, or preachy.
`,
  };

  return `${commonRules}\n${modeGuidance[mode] || ""}${toneProfileText(toneProfile)}${contextText(context)}${styleText(style)}${goalText(goal)}${draftText(draft)}\n${outputFormat}`;
}

/* Batch 4: AI scores must be integers 1-10; a missing or out-of-range score falls back to 6, never 0 or 11. */
function clampScoreOut(v) {
  if (v === null || v === undefined || v === "") return 6; /* missing score */
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(10, Math.max(1, Math.round(n))) : 6;
}
function clampDraftScoreOut(v) {
  if (v === null || v === undefined || v === "") return 50; /* missing draft score */
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(100, Math.max(1, Math.round(n))) : 50;
}
/* Normalise the 3 tactical replies. A missing/invalid reply falls back
   to the existing versions in order — Hold the Line <- better_version,
   De-escalate <- softer_version, Strategic Pivot <- stronger_version —
   so an old or partial model answer still shows 3 copy-pasteable replies. */
function normaliseReplies(data, fallback) {
  const strategies = ["Hold the Line (Firm)", "De-escalate (Neutral)", "Strategic Pivot (Reframe)"];
  const src = fallback || data || {};
  const fallbacks = [
    { message: src.better_version || "", why_it_works: "The best balanced version for this situation." },
    { message: src.softer_version || "", why_it_works: "A gentler version that lowers the temperature." },
    { message: src.stronger_version || "", why_it_works: "A firmer version that reframes the exchange on your terms." },
  ];
  const given = Array.isArray(data && data.replies) ? data.replies : [];
  return strategies.map(function (strategy, i) {
    const r = given[i];
    const message = r && typeof r.message === "string" && r.message.trim() ? r.message.trim() : fallbacks[i].message;
    const why = r && typeof r.why_it_works === "string" && r.why_it_works.trim() ? r.why_it_works.trim() : fallbacks[i].why_it_works;
    return { strategy: strategy, message: message, why_it_works: why };
  });
}
function formatFallback(mode, message, data, hasDraft) {
  const betterVersion = data?.better_version || message;
  const softerVersion = data?.softer_version || message;
  const strongerVersion = data?.stronger_version || message;
  return {
    mode,
    original_message: message,
    tone_detected: data?.tone_detected || "Unclear",
    intent_guess: data?.intent_guess || "Improve the message",
    risk_level: data?.risk_level || "medium",
    should_send: data?.should_send || "edit_first",
    why_it_might_land_badly:
      data?.why_it_might_land_badly ||
      "The message may be misunderstood or come across differently than intended.",
    better_version: betterVersion,
    softer_version: softerVersion,
    stronger_version: strongerVersion,
    power_dynamic:
      (typeof data?.power_dynamic === "string" && data.power_dynamic.trim())
        ? data.power_dynamic.trim()
        : "The other person holds the immediate leverage in this exchange — watch for pressure tactics and keep your reply short and factual.",
    emotional_trap:
      (typeof data?.emotional_trap === "string" && data.emotional_trap.trim())
        ? data.emotional_trap.trim()
        : "Replying defensively is likely to escalate the exchange and hand the other person the reaction they want.",
    draft_critique: (function () {
      if (!hasDraft) return null;
      const c = data?.draft_critique;
      if (c && typeof c === "object") {
        return {
          score: clampDraftScoreOut(c.score),
          flaw: (typeof c.flaw === "string" && c.flaw.trim()) ? c.flaw.trim() : "The draft does not state a clear boundary or outcome.",
        };
      }
      return { score: 50, flaw: "The draft does not state a clear boundary or outcome." };
    })(),
    replies: normaliseReplies(data, { better_version: betterVersion, softer_version: softerVersion, stronger_version: strongerVersion }),
    coach_note:
      data?.coach_note ||
      "Make the message clearer, calmer, and more intentional before sending.",
    scores: {
      clarity: clampScoreOut(data?.scores?.clarity),
      confidence: clampScoreOut(data?.scores?.confidence),
      emotional_control: clampScoreOut(data?.scores?.emotional_control),
      effectiveness: clampScoreOut(data?.scores?.effectiveness),
    },
  };
}

/* ---------- Sprint 2: Multi-Screenshot Thread Engine ----------
   POST /analyze-thread (below, after /analyze) sends up to 5 screenshots
   to a vision model. Images are Base64 in memory only — never written
   to disk, never stored, never logged — and dropped after the response.
   Sprint 2 fix pass: the vision model is no longer hardcoded. Provider
   selection (selectVisionProvider, checked in this order):
     1. MOCK_AI=true — LOCAL TESTING ONLY. Returns a realistic sample
        (buildMockThreadResult) through the same shaping/fallbacks as the
        real path, so the full UI flow can be tested with no API credits.
        Never set MOCK_AI on Render.
     2. GEMINI_API_KEY set — gemini-3.8-flash via plain fetch, multimodal
        image inputs, structured JSON output. No new npm dependency.
     3. OPENAI_API_KEY set — process.env.OPENAI_VISION_MODEL or
        "gpt-4.1-mini" (Sprint 2 used gpt-4o; the default changed here).
   The text endpoint stays on gpt-5.4-nano.
   No cache for thread analyses: two threads can look alike in text
   but differ in images, so a cached result could be stale for a
   different thread. */
const OPENAI_VISION_MODEL = process.env.OPENAI_VISION_MODEL || "gpt-4.1-mini";
const GEMINI_VISION_MODEL = "gemini-3.8-flash";
const THREAD_MAX_IMAGES = 5;
const THREAD_MAX_TOTAL_BYTES = 6 * 1024 * 1024; /* decoded image bytes, in total - under the 10mb JSON limit, so an over-cap thread gets this friendly 413 instead of a parser error */
const THREAD_MAX_IMAGE_BYTES = 2 * 1024 * 1024; /* decoded bytes per single image — one huge screenshot gets a friendly 413 even when the total is under 6MB */
function selectVisionProvider() {
  if (process.env.MOCK_AI === "true") return { provider: "mock" };
  if (process.env.GEMINI_API_KEY) return { provider: "gemini", model: GEMINI_VISION_MODEL };
  if (process.env.OPENAI_API_KEY) return { provider: "openai", model: OPENAI_VISION_MODEL };
  return { provider: "none" };
}
function buildMockThreadResult(mode, imageCount, goal, hasDraft) {
  /* Sprint 2 fix pass — MOCK_AI sample data. A generic workplace thread
     (a manager pressing for a quick yes on a weekend shift), clearly a
     sample: it never claims to be the user's real thread. It matches the
     saved schema exactly (power_dynamic, emotional_trap, draft_critique,
     replies exactly 3, pattern_summary exactly 15 words) and goes through
     formatThreadFallback like a real provider response. */
  return {
    mode: mode,
    original_message: "Sample thread (" + imageCount + " images) — a manager pressing for a quick yes on a weekend shift",
    tone_detected: "Pressuring",
    intent_guess: "Push for a quick yes before the user can check their calendar",
    risk_level: "medium",
    should_send: "edit_first",
    why_it_might_land_badly: "Saying yes now sets a precedent that weekend shifts are always available.",
    better_version: "Thanks for thinking of me — I need to check my calendar and will confirm by Friday.",
    softer_version: "Thanks for asking — let me check what I have on and get back to you by Friday.",
    stronger_version: "I can't take the weekend shift, but I can cover Tuesday if that helps.",
    coach_note: "The riskiest phrase is the implied deadline — answer the ask, not the urgency.",
    power_dynamic: "The manager holds the scheduling leverage in this exchange. They are using false urgency to force a quick yes before the user can think.",
    emotional_trap: "Replying defensively will make the user look uncommitted and hand the manager the reaction they want.",
    draft_critique: hasDraft ? { score: 42, flaw: "The draft apologises for a reasonable boundary instead of stating it." } : null,
    replies: [
      { strategy: "Hold the Line (Firm)", message: "I can't take the weekend shift.", why_it_works: "One clear no, no over-explaining." },
      { strategy: "De-escalate (Neutral)", message: "Let me check my calendar and confirm by Friday.", why_it_works: "Buys time without conceding." },
      { strategy: "Strategic Pivot (Reframe)", message: "I can't do the weekend, but I can cover Tuesday instead — does that help?", why_it_works: "Offers an alternative on the user's terms." },
    ],
    pattern_summary: "The other person used pressure and urgency to push for a quick yes today again.",
    scores: { clarity: 8, confidence: 7, emotional_control: 9, effectiveness: 8 },
  };
}
const VISION_UPSTREAM_ERROR = "The AI service couldn't be reached right now. Please try again in a moment.";
function mapVisionUpstreamError(error) {
  /* Sprint 2 fix pass: upstream 401/403/429 become a generic friendly
     error — no raw provider strings, no keys, no status details leaked.
     Only the status is ever logged, never the provider's message. */
  const status = error && (error.status || (error.response && error.response.status));
  if (status === 429) return { status: 429, error: "Too many requests to the AI service right now. Please wait a minute and try again." };
  if (status === 401 || status === 403) return { status: 502, error: VISION_UPSTREAM_ERROR };
  if (error && error.name === "AbortError") return { status: 502, error: VISION_UPSTREAM_ERROR };
  return { status: 500, error: "Something went wrong. Please try again." };
}
async function callGeminiVision(prompt, images) {
  /* Sprint 2 fix pass: Gemini via plain fetch — no new npm dependency.
     Images go as inline_data parts (mime_type + base64); the model must
     return JSON (responseMimeType application/json). Throws an Error with
     a .status on HTTP failure so the route can map 401/403/429 cleanly. */
  const parts = [{ text: prompt }];
  images.forEach(function (url) {
    const m = url.match(/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/);
    if (m) parts.push({ inline_data: { mime_type: "image/" + m[1], data: m[2] } });
  });
  const res = await fetch("https://generativelanguage.googleapis.com/v1beta/models/" + GEMINI_VISION_MODEL + ":generateContent?key=" + encodeURIComponent(process.env.GEMINI_API_KEY || ""), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ parts: parts }], generationConfig: { responseMimeType: "application/json", temperature: 0.7 } }),
    signal: AbortSignal.timeout(60000),
  });
  if (!res.ok) { const e = new Error("Gemini request failed"); e.status = res.status; throw e; }
  const data = await res.json().catch(function () { return null; });
  const text = data && data.candidates && data.candidates[0] && data.candidates[0].content && Array.isArray(data.candidates[0].content.parts)
    ? data.candidates[0].content.parts.map(function (p) { return typeof p.text === "string" ? p.text : ""; }).join("")
    : "";
  if (!text.trim()) throw new Error("Gemini returned no text");
  return text;
}
function sanitiseThreadImages(input) {
  if (!Array.isArray(input)) return { error: "Add at least 1 screenshot to analyse a thread.", status: 400 };
  if (input.length === 0) return { error: "Add at least 1 screenshot to analyse a thread.", status: 400 };
  if (input.length > THREAD_MAX_IMAGES) return { error: "You can upload up to 5 screenshots in a thread.", status: 400 };
  let totalBytes = 0;
  for (let i = 0; i < input.length; i++) {
    const img = input[i];
    if (typeof img !== "string") return { error: "Each screenshot must be a JPEG, PNG or WebP image.", status: 400 };
    const m = img.match(/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/);
    if (!m) return { error: "Each screenshot must be a JPEG, PNG or WebP image.", status: 400 };
    const decodedBytes = Math.floor(m[2].length * 3 / 4);
    if (decodedBytes > THREAD_MAX_IMAGE_BYTES) return { error: "One screenshot is too large — try a smaller screenshot (max 2MB each).", status: 413 };
    totalBytes += decodedBytes;
  }
  if (totalBytes > THREAD_MAX_TOTAL_BYTES) return { error: "Screenshots are too large in total — try fewer or smaller screenshots.", status: 413 };
  return { images: input };
}
function patternSummary15(summary) {
  const fallback = "The other person used pressure and urgency to push for a quick yes today again.";
  const words = typeof summary === "string" ? summary.trim().split(/\s+/).filter(Boolean) : [];
  if (!words.length) return fallback;
  return words.slice(0, 15).join(" ");
}
function buildThreadPrompt(mode, toneProfile, context, goal, draft) {
  const laneGuidance = {
    career: `\nMode: Career & Boss\nOptimize for pushback, raises, boundary setting, and covering yourself for HR. Document facts, stay professional, and keep a paper trail in the wording.\nAvoid sounding emotional, passive-aggressive, or apologetic about reasonable boundaries.\n`,
    negotiation: `\nMode: Client & Negotiation\nOptimize for scope creep, pricing pushback, and closing deals. Be firm on value, name clear terms, and never concede without getting something back.\nAvoid sounding needy, overexplaining, or defensive.\n`,
    high_conflict: `\nMode: High-Conflict / Legal & Co-Parenting — STRICT BIFF\nBIFF only: Brief, Informative, Friendly, Firm. Keep every version short and factual. State only what happened, what you need, or what will happen next.\nNo emotional hooks, no blame, no sarcasm, no advice about the other person, no rehashing history.\n`,
    boundaries: `\nMode: Hard Personal Boundaries\nOptimize for saying no to family and friends without blowing up the relationship. Warm but firm: one clear no, no over-explaining, no justifying, no apologising for the boundary itself.\nAvoid sounding cold, guilty, or preachy.\n`,
  };
  return `You are BeforeYouSay, an elite AI communication coach.
Read the screenshots IN ORDER as one chronological thread — screenshot 1 happened first, the last screenshot happened last. Use bubble alignment and timestamps in the screenshots to tell who said what and when. Do not sound robotic. Do not use emojis.
${laneGuidance[mode] || laneGuidance.career}${toneProfileText(toneProfile)}${contextText(context)}
User's exact goal: ${goal}
Judge every version against that goal — the best version is the one most likely to achieve it.${draftText(draft)}
Return valid JSON only in this exact structure:
{
  "mode": "string",
  "original_message": "string — describe the thread in one line, e.g. the topic of the exchange",
  "tone_detected": "string",
  "intent_guess": "string",
  "risk_level": "low | medium | high",
  "should_send": "yes | edit_first | no",
  "why_it_might_land_badly": "string",
  "better_version": "string",
  "softer_version": "string",
  "stronger_version": "string",
  "coach_note": "string",
  "power_dynamic": "string",
  "emotional_trap": "string",
  "draft_critique": "object or null",
  "replies": [
    { "strategy": "Hold the Line (Firm)", "message": "string", "why_it_works": "string" },
    { "strategy": "De-escalate (Neutral)", "message": "string", "why_it_works": "string" },
    { "strategy": "Strategic Pivot (Reframe)", "message": "string", "why_it_works": "string" }
  ],
  "pattern_summary": "string — exactly 15 words: a summary of the other person's behavior",
  "scores": { "clarity": 0, "confidence": 0, "emotional_control": 0, "effectiveness": 0 }
}
Rules:
- Scores must be integers from 1 to 10 and must match the text; never give all four scores the same number.
- power_dynamic must be exactly 2 sentences: who has the leverage in this exchange, and what tactic the other person is using (for example guilt-tripping, false urgency, or moving the goalposts).
- emotional_trap must be exactly 1 sentence: what happens if the user replies defensively.
- draft_critique is null when no draft was provided. When a draft was provided, it is {"score": 0-100, "flaw": "the exact flaw in 1 sentence"} — score how well the draft serves the user's goal.
- replies must be exactly 3, in this order, with these exact strategy labels: "Hold the Line (Firm)", "De-escalate (Neutral)", "Strategic Pivot (Reframe)". Each message is the exact copy-pasteable text the user can send; each why_it_works is 1 line.
- pattern_summary must be exactly 15 words.
- coach_note should be short and useful: name the single riskiest phrase in the thread and give one concrete fix for it.
`;
}
function formatThreadFallback(mode, imageCount, data, hasDraft, goal) {
  const label = "Screenshot thread (" + imageCount + " image" + (imageCount === 1 ? "" : "s") + ")";
  const base = formatFallback(mode, label, data, hasDraft);
  base.original_message = (typeof data?.original_message === "string" && data.original_message.trim()) ? data.original_message.trim() : label;
  base.pattern_summary = patternSummary15(data?.pattern_summary);
  return base;
}

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: "Too many requests. Please wait a minute and try again." },
});
function buildReplyPrompt(mode, toneProfile, style, context, goal, draft) {
  const modeInstructions = {
    career: `You are helping someone reply professionally to a message they received at work — from a boss, colleague, or HR. Replies must be calm, clear, and boundary-aware, and cover the user for HR: facts first, no admissions, no emotion. No slang. Keep it respectful and concise.`,
    negotiation: `You are helping someone reply in a client or commercial negotiation to a message they received. Replies must be assertive, strategic, and calm. Hold the line on scope and price, name clear terms, and show leverage without desperation. Stay in control.`,
    high_conflict: `You are helping someone reply to a high-conflict, legal, or co-parenting message. Use STRICT BIFF only: Brief, Informative, Friendly, Firm. Short, factual replies. No emotional hooks, no blame, no sarcasm, no advice about the other person, no rehashing history.`,
    boundaries: `You are helping someone reply to family or a friend when they need to hold a hard boundary. Replies must be warm but firm: one clear no, no over-explaining, no justifying. No guilt, no coldness, no blowing up the relationship.`
  };

  return `
You are BeforeYouSay, an elite AI communication coach.

The user RECEIVED a message from someone else and needs help replying back.
Write 3 replies FROM the user, responding TO the sender of that message.

${modeInstructions[mode] || modeInstructions.career}

IMPORTANT EXAMPLES:
- Received: "we need to talk about your performance"
  ✅ Correct reply: "Sure, happy to connect. When works for you?"
  ❌ Wrong reply: "We need to discuss your performance and align on next steps."

- Received: "are you free to hop on a quick call?"
  ✅ Correct reply: "Sure — now works, or after 3pm?"
  ❌ Wrong reply: "You are asking me if I am free for a call."

Return valid JSON only in this exact structure:
{
  "tone_detected": "string — the tone of the message they received",
  "why_it_might_land_badly": "string — what to watch out for when replying",
  "better_version": "string — the best balanced reply the user can send back",
  "softer_version": "string — a softer or warmer reply the user can send back",
  "stronger_version": "string — a more direct or assertive reply the user can send back",
  "coach_note": "string — one short tactical tip for this specific situation",
  "power_dynamic": "string — 2 sentences: who has leverage, and what tactic the sender is using",
  "emotional_trap": "string — 1 sentence: what happens if the user replies defensively",
  "draft_critique": "object or null — when the user provided a draft: {"score": 0-100, "flaw": "the exact flaw in 1 sentence"}; null when no draft was provided",
  "replies": [
    { "strategy": "Hold the Line (Firm)", "message": "string — the exact reply to send", "why_it_works": "string — 1 line" },
    { "strategy": "De-escalate (Neutral)", "message": "string — the exact reply to send", "why_it_works": "string — 1 line" },
    { "strategy": "Strategic Pivot (Reframe)", "message": "string — the exact reply to send", "why_it_works": "string — 1 line" }
  ],
  "risk_level": "low | medium | high — judge the received message, never leave it fixed",
  "should_send": "yes | edit_first | no — judge whether the best reply is safe to send as written",
  "intent_guess": "string — what the sender likely meant",
  "original_message": "",
  "scores": { "clarity": 0, "confidence": 0, "emotional_control": 0, "effectiveness": 0 }
}

Rules:
- The user is the RECIPIENT. All 3 replies are what THEY send back to the other person.
- Never rewrite or rephrase the received message from the sender's perspective.
- Replies must match the mode tone strictly.
- Keep replies short and natural. No corporate speak. No over-explaining.
- coach_note must be one punchy sentence of tactical advice.
- Judge risk_level, should_send and the four scores from the received message and your replies — never leave them at fixed values. Scores are integers 1-10 and must differ where the reply's qualities differ.
- power_dynamic must be exactly 2 sentences (leverage + the sender's tactic); emotional_trap exactly 1 sentence. draft_critique is null when no draft was provided. replies must be exactly 3, in order, with the exact strategy labels "Hold the Line (Firm)", "De-escalate (Neutral)", "Strategic Pivot (Reframe)" — each message the exact copy-pasteable reply, each why_it_works 1 line.
${toneProfileText(toneProfile)}${contextText(context)}${styleText(style)}${goalText(goal)}${draftText(draft)}
`;
}
/* ---------- Batch 1 trust+control: delete my account ----------
   POST /delete-account deletes a signed-in user's rows (profiles,
   history, contexts) and then their Supabase auth user. It needs two
   Render env vars, set on the Render dashboard only, never in code:
   SUPABASE_URL (the Sydney project URL) and SUPABASE_SERVICE_ROLE_KEY.
   The service-role key bypasses RLS, so it must never go in the
   frontend, in Git, or in chat. If it is not set, the endpoint answers
   503 and deletes nothing — the frontend still deletes the user's own
   cloud rows directly (RLS lets each user delete only their own rows)
   and says so plainly. The user's token is checked by asking Supabase
   itself (GET /auth/v1/user with the service-role key), so no JWT
   secret or HS256/ES256 check is needed here. Rate limited to 3
   attempts per hour per IP. No token or key is ever logged. */
const deleteLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: "Too many delete requests. Please try again later." },
});
const SUPABASE_URL = (process.env.SUPABASE_URL || "https://vtupfkaaixqucymiggux.supabase.co").replace(/\/$/, "");
async function supabaseAdminRequest(path, method) {
  const res = await fetch(SUPABASE_URL + path, {
    method: method,
    headers: { apikey: process.env.SUPABASE_SERVICE_ROLE_KEY, Authorization: "Bearer " + process.env.SUPABASE_SERVICE_ROLE_KEY },
  });
  return res;
}
async function getSupabaseUserFromToken(token) {
  try {
    const res = await fetch(SUPABASE_URL + "/auth/v1/user", {
      headers: { apikey: process.env.SUPABASE_SERVICE_ROLE_KEY, Authorization: "Bearer " + token },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data && data.id ? data : null;
  } catch (e) { return null; }
}
async function supabaseAdminDeleteRows(table, column, userId) {
  try {
    const res = await supabaseAdminRequest("/rest/v1/" + table + "?" + column + "=eq." + encodeURIComponent(userId), "DELETE");
    return res.ok;
  } catch (e) { return false; }
}
app.post("/delete-account", deleteLimiter, async (req, res) => {
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(503).json({ deleted: false, rowsDeleted: false, authUserDeleted: false, error: "Account deletion is not set up on the server yet." });
  }
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({ deleted: false, rowsDeleted: false, authUserDeleted: false, error: "Sign-in is required to delete an account." });
  }
  const user = await getSupabaseUserFromToken(h.slice(7).trim());
  if (!user) {
    return res.status(401).json({ deleted: false, rowsDeleted: false, authUserDeleted: false, error: "Your sign-in could not be checked. Please sign in again and try." });
  }
  const userId = user.id;
  const rows = await Promise.all([
    supabaseAdminDeleteRows("history", "user_id", userId),
    supabaseAdminDeleteRows("contexts", "user_id", userId),
    supabaseAdminDeleteRows("profiles", "id", userId),
  ]);
  const rowsDeleted = rows.every(Boolean);
  let authUserDeleted = false;
  try {
    const delRes = await supabaseAdminRequest("/auth/v1/admin/users/" + encodeURIComponent(userId), "DELETE");
    authUserDeleted = delRes.ok;
  } catch (e) { authUserDeleted = false; }
  if (!authUserDeleted) {
    return res.status(200).json({ deleted: false, rowsDeleted: rowsDeleted, authUserDeleted: false, error: "Your data was deleted, but the sign-in account itself could not be removed. Please contact support and we will remove it." });
  }
  return res.json({ deleted: true, rowsDeleted: rowsDeleted, authUserDeleted: true });
});

/* ---------- Batch 8 Pro checkout: Stripe Checkout + plan changes ----------
   Pro is sold through Stripe Checkout (test mode for now). Two pieces:
   - POST /create-checkout-session: signed-in users only. Checks the
     Supabase token the same way /delete-account does, then asks Stripe
     for a Checkout session for the Monthly or Yearly price and returns
     its URL. The frontend sends the user there; Stripe handles the card.
   - The /stripe-webhook route above: Stripe tells us the payment
     happened, and we set that user's profiles.plan to "pro" (or back
     to "free" when the subscription ends). The plan is never trusted
     from the frontend — only a signature-checked Stripe event changes it.
   No new dependency: Stripe is called with plain fetch, the same way
   Supabase and Turnstile already are. The price IDs below are public
   identifiers (they appear in Checkout URLs), not secrets — but they
   can be overridden with env vars, which is how the live prices will
   be swapped in later without a code change. STRIPE_SECRET_KEY (test
   key for now) and STRIPE_WEBHOOK_SECRET live on Render only, never
   in code. No GST is collected: Stripe Tax is not enabled, and no tax
   settings are sent with the session. */
const STRIPE_PRICE_IDS = {
  monthly: process.env.STRIPE_PRICE_MONTHLY || "price_1Ud7JPJAED4eiF02w6iDmDhP", /* test: AUD $5/month */
  yearly: process.env.STRIPE_PRICE_YEARLY || "price_1Ud7JUJAED4eiF02V37Pv1tR", /* test: AUD $50/year */
};
const STRIPE_SITE_URL = "https://www.beforeyousay.com";

function sanitiseBilling(input) {
  return input === "monthly" || input === "yearly" ? input : null;
}

async function stripeApiPost(path, params) {
  try {
    const res = await fetch("https://api.stripe.com" + path, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + process.env.STRIPE_SECRET_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(params),
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json().catch(function () { return null; });
    return { ok: res.ok, status: res.status, data: data };
  } catch (e) { return { ok: false, status: 0, data: null }; }
}

/* Batch 11: Stripe GET (subscription lookup + subscription search for
   /cancel-subscription). Same shape as stripeApiPost, minus the body. */
async function stripeApiGet(path) {
  try {
    const res = await fetch("https://api.stripe.com" + path, {
      headers: { Authorization: "Bearer " + process.env.STRIPE_SECRET_KEY },
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json().catch(function () { return null; });
    return { ok: res.ok, status: res.status, data: data };
  } catch (e) { return { ok: false, status: 0, data: null }; }
}

/* Stripe signs every webhook: header "t=<timestamp>,v1=<signature>".
   The signature is HMAC-SHA256 of "<timestamp>.<raw body>" with the
   webhook secret. We check the timestamp is fresh (5 minutes) and the
   signature matches one of the v1 values, in constant time. */
function verifyStripeSignature(rawBody, signatureHeader, secret) {
  if (!secret || !signatureHeader) return false;
  let ts = null;
  const sigs = [];
  String(signatureHeader).split(",").forEach(function (part) {
    const p = part.trim();
    if (p.indexOf("t=") === 0) ts = p.slice(2);
    else if (p.indexOf("v1=") === 0) sigs.push(p.slice(3));
  });
  if (!ts || !sigs.length) return false;
  const age = Math.abs(Date.now() / 1000 - Number(ts));
  if (!Number.isFinite(age) || age > 300) return false; /* stale: replay */
  const bodyText = Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : String(rawBody);
  const expected = crypto.createHmac("sha256", secret).update(ts + "." + bodyText, "utf8").digest("hex");
  return sigs.some(function (sig) {
    try {
      const a = Buffer.from(sig, "hex");
      const b = Buffer.from(expected, "hex");
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch (e) { return false; }
  });
}

/* Pure mapping from a Stripe event to a plan change — nothing else in
   the file needs to know Stripe's event shapes. Returns null for
   events we ignore. The user id travels in metadata: the checkout
   session carries it (metadata + client_reference_id), and the
   subscription inherits it (subscription_data.metadata), so later
   subscription events can find the same user.
   Batch 11: the result also carries the Stripe customer id, the
   subscription id and the period end, so the webhook can store them
   on the profile row and /cancel-subscription can find the
   subscription later. planEndsAt is an ISO string to set, null to
   clear the column (subscription gone), or undefined to leave it
   alone (the event says nothing about the period end). */
function stripePeriodEndIso(sub) {
  const ts = sub && typeof sub.current_period_end === "number" ? sub.current_period_end : null;
  if (!ts) return undefined;
  const d = new Date(ts * 1000);
  return Number.isFinite(d.getTime()) ? d.toISOString() : undefined;
}
function stripeCustomerIdOf(sub) {
  if (!sub) return undefined;
  if (typeof sub.customer === "string") return sub.customer;
  if (sub.customer && typeof sub.customer.id === "string") return sub.customer.id;
  return undefined;
}
function planFromStripeEvent(event) {
  if (!event || typeof event.type !== "string") return null;
  const data = event.data && event.data.object ? event.data.object : null;
  if (!data) return null;
  const userId = (data.metadata && data.metadata.user_id) || data.client_reference_id || null;
  if (event.type === "checkout.session.completed") {
    if (data.mode !== "subscription" || data.payment_status !== "paid") return null;
    /* The period end is not on the session — the subscription.created
       event that follows carries it, so leave plan_ends_at alone here. */
    return userId ? { userId: userId, plan: "pro", stripeCustomerId: typeof data.customer === "string" ? data.customer : undefined, stripeSubscriptionId: typeof data.subscription === "string" ? data.subscription : undefined, planEndsAt: undefined } : null;
  }
  if (event.type === "customer.subscription.created") {
    if (!userId) return null;
    if (data.status === "active" || data.status === "trialing") return { userId: userId, plan: "pro", stripeCustomerId: stripeCustomerIdOf(data), stripeSubscriptionId: typeof data.id === "string" ? data.id : undefined, planEndsAt: stripePeriodEndIso(data) };
    return null;
  }
  if (event.type === "customer.subscription.updated") {
    if (!userId) return null;
    /* Cancel-at-period-end lands here: status stays "active", so the
       plan stays "pro" — but the period end is now the date Pro runs
       out, and the site shows "Pro until <date>". */
    if (data.status === "active" || data.status === "trialing") return { userId: userId, plan: "pro", stripeCustomerId: stripeCustomerIdOf(data), stripeSubscriptionId: typeof data.id === "string" ? data.id : undefined, planEndsAt: stripePeriodEndIso(data) };
    if (data.status === "canceled" || data.status === "incomplete_expired") return { userId: userId, plan: "free", stripeCustomerId: stripeCustomerIdOf(data), stripeSubscriptionId: null, planEndsAt: null };
    return null; /* past_due / unpaid / incomplete: Stripe retries payment; the plan stays until the subscription is actually cancelled */
  }
  if (event.type === "customer.subscription.deleted") {
    return userId ? { userId: userId, plan: "free", stripeCustomerId: stripeCustomerIdOf(data), stripeSubscriptionId: null, planEndsAt: null } : null;
  }
  return null;
}

/* Upsert, not update: a user who goes straight from sign-up to checkout
   may not have a profiles row yet (the row is normally made on first
   sync). The row's other columns all have defaults or are nullable,
   so id + plan is enough. Service-role key only — never the anon key. */
/* Upsert, not update: a user who goes straight from sign-up to checkout
   may not have a profiles row yet (the row is normally made on first
   sync). The row's other columns all have defaults or are nullable,
   so id + plan is enough. Service-role key only — never the anon key.
   Batch 11: the general version upserts any profile fields (plan,
   stripe ids, period end). A field set to undefined is left out of
   the body, so an event that says nothing about it cannot wipe a
   value another event stored; a field set to null IS sent, which
   clears that column (used when a subscription is deleted). */
async function supabaseAdminUpsertProfileFields(userId, fields) {
  const body = { id: userId, updated_at: new Date().toISOString() };
  Object.keys(fields || {}).forEach(function (k) { if (fields[k] !== undefined) body[k] = fields[k]; });
  try {
    const res = await fetch(SUPABASE_URL + "/rest/v1/profiles?on_conflict=id", {
      method: "POST",
      headers: {
        apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: "Bearer " + process.env.SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      let bodyText = "";
      try { bodyText = await res.text(); } catch (e2) { bodyText = ""; }
      console.error("Supabase profile upsert failed:", res.status, bodyText);
      return false;
    }
    return true;
  } catch (e) { console.error("Supabase profile upsert error:", e && e.message ? e.message : e); return false; }
}
async function supabaseAdminUpsertPlan(userId, plan) {
  return supabaseAdminUpsertProfileFields(userId, { plan: plan });
}

const checkoutLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: "Too many checkout attempts. Please try again later." },
});

app.post("/create-checkout-session", checkoutLimiter, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(503).json({ error: "Checkout is not set up on the server yet." });
  }
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Sign-in is required to upgrade to Pro." });
  }
  const user = await getSupabaseUserFromToken(h.slice(7).trim());
  if (!user) {
    return res.status(401).json({ error: "Your sign-in could not be checked. Please sign in again and try." });
  }
  const billing = sanitiseBilling(req.body && req.body.billing);
  if (!billing) {
    return res.status(400).json({ error: "Choose Monthly or Yearly to upgrade to Pro." });
  }
  const priceId = STRIPE_PRICE_IDS[billing];
  const result = await stripeApiPost("/v1/checkout/sessions", {
    mode: "subscription",
    "line_items[0][price]": priceId,
    "line_items[0][quantity]": "1",
    client_reference_id: user.id,
    customer_email: user.email || "",
    "metadata[user_id]": user.id,
    "metadata[billing]": billing,
    "subscription_data[metadata][user_id]": user.id,
    /* Batch 12: the return URL carries the Checkout session id, so
       the site can look the payment up when Stripe sends the user back
       and say plainly which account paid. Stripe replaces
       {CHECKOUT_SESSION_ID} with the real session id. */
    success_url: STRIPE_SITE_URL + "/?checkout=success&session_id={CHECKOUT_SESSION_ID}",
    cancel_url: STRIPE_SITE_URL + "/?checkout=cancelled",
  });
  if (!result.ok || !result.data || !result.data.url) {
    console.error("Stripe checkout error:", result.status, result.data && result.data.error ? result.data.error.message : "no response");
    return res.status(502).json({ error: "Checkout could not be started. Please try again." });
  }
  return res.json({ url: result.data.url });
});

/* ---------- Batch 12 Stripe return fix ----------
   After paying, Stripe sends the user back to /?checkout=success —
   and twice now (test mode, then the live $5 payment) Sagar landed
   back signed out, feeling locked out. The payment itself was fine
   both times (the webhook had already flipped the plan to Pro), but
   the site could not say WHO had just paid, so a user who signs back
   in as the wrong account sees Free and thinks the payment vanished.
   Fix: the success_url now carries the Checkout session id, and this
   lookup endpoint lets the site ask Stripe who paid.
   GET /checkout-session?session_id=cs_... — no sign-in required (the
   user is signed out at exactly this moment). It fetches that session
   from Stripe and returns ONLY the paying customer's email and the
   current plan for the user id in the session metadata (looked up with
   the service-role key, the same way the webhook does). It never
   returns keys, tokens, full customer records or other users' data.
   A session that is not a paid subscription, or has no user id or
   email, is a 404 — the same as an unknown id. Rate limited to 10
   lookups per hour per IP, like checkout. No token or key is ever
   logged. */
function checkoutSessionDetails(session) {
  if (!session || typeof session !== "object") return null;
  if (session.mode !== "subscription" || session.payment_status !== "paid") return null;
  const userId = (session.metadata && session.metadata.user_id) || session.client_reference_id || null;
  if (!userId) return null;
  const email = (session.customer_details && session.customer_details.email) || session.customer_email || null;
  if (!email) return null;
  return { userId: userId, email: email };
}
const checkoutLookupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: "Too many payment lookups. Please try again later." },
});
app.get("/checkout-session", checkoutLookupLimiter, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(503).json({ error: "Checkout lookup is not set up on the server yet." });
  }
  const sessionId = typeof req.query.session_id === "string" ? req.query.session_id.trim() : "";
  if (!sessionId || sessionId.indexOf("cs_") !== 0) {
    return res.status(400).json({ error: "That payment link doesn't look right. Sign in and check Your account — your Pro will show there if the payment went through." });
  }
  const got = await stripeApiGet("/v1/checkout/sessions/" + encodeURIComponent(sessionId));
  if (!got.ok || !got.data || !got.data.id) {
    if (got.status === 404) return res.status(404).json({ error: "We couldn't find that payment. If you paid, sign in and check Your account — your Pro will show there." });
    console.error("Stripe checkout session lookup error:", got.status);
    return res.status(502).json({ error: "We couldn't check that payment right now. Sign in and check Your account — your Pro will show there if the payment went through." });
  }
  const details = checkoutSessionDetails(got.data);
  if (!details) {
    return res.status(404).json({ error: "We couldn't find that payment. If you paid, sign in and check Your account — your Pro will show there." });
  }
  const profile = await supabaseAdminGetProfile(details.userId);
  return res.json({ email: details.email, plan: profile && profile.plan ? profile.plan : "free" });
});

/* ---------- Batch 11 self-serve cancel ----------
   POST /cancel-subscription lets a signed-in Pro user cancel Pro
   themselves. Policy (Sagar's choice): the subscription is cancelled
   at the end of the paid period (cancel_at_period_end) — the user
   keeps Pro until then, then drops to Free automatically when Stripe
   ends the subscription. No automatic refund; refunds are on request
   by email (see the site's refund note).
   Finding the subscription: the profile row normally carries the
   Stripe subscription id (the webhook stores it on every payment
   event). Users who paid before Batch 11 have no id stored, so the
   endpoint falls back to a Stripe search by the user id in the
   subscription metadata — and backfills the row when it finds one.
   Safety: the subscription's own metadata user_id must match the
   signed-in user before anything is cancelled, so a tampered or
   stale profile row can never cancel someone else's Pro. Rate
   limited to 10 attempts per hour per IP, like checkout. No token
   or key is ever logged. */
const cancelLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: "Too many cancellation attempts. Please try again later." },
});
async function supabaseAdminGetProfile(userId) {
  try {
    const res = await fetch(SUPABASE_URL + "/rest/v1/profiles?select=plan,stripe_customer_id,stripe_subscription_id,plan_ends_at&id=eq." + encodeURIComponent(userId), {
      headers: { apikey: process.env.SUPABASE_SERVICE_ROLE_KEY, Authorization: "Bearer " + process.env.SUPABASE_SERVICE_ROLE_KEY },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const rows = await res.json();
    return Array.isArray(rows) && rows[0] ? rows[0] : null;
  } catch (e) { return null; }
}
async function stripeFindSubscriptionByUserId(userId) {
  const query = "metadata['user_id']:'" + userId + "'";
  const result = await stripeApiGet("/v1/subscriptions/search?query=" + encodeURIComponent(query) + "&limit=10");
  if (!result.ok || !result.data || !Array.isArray(result.data.data)) return { found: null, error: !result.ok };
  const live = result.data.data.filter(function (s) { return s.status === "active" || s.status === "trialing"; });
  return { found: live[0] || null, error: false };
}
const NO_SUBSCRIPTION_MESSAGE = "No active Pro subscription was found on your account. If you paid and think this is wrong, email us and we'll sort it out.";
app.post("/cancel-subscription", cancelLimiter, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(503).json({ error: "Cancellation is not set up on the server yet." });
  }
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Sign-in is required to cancel Pro." });
  }
  const user = await getSupabaseUserFromToken(h.slice(7).trim());
  if (!user) {
    return res.status(401).json({ error: "Your sign-in could not be checked. Please sign in again and try." });
  }
  let subId = null;
  let sub = null;
  const profile = await supabaseAdminGetProfile(user.id);
  if (profile && profile.stripe_subscription_id) subId = profile.stripe_subscription_id;
  if (!subId) {
    const found = await stripeFindSubscriptionByUserId(user.id);
    if (found.error) {
      console.error("Stripe subscription search error");
      return res.status(502).json({ error: "Cancellation couldn't be completed. Please try again." });
    }
    if (found.found) {
      sub = found.found;
      subId = sub.id;
      /* Backfill the row so the next cancel finds it straight away. */
      await supabaseAdminUpsertProfileFields(user.id, { stripe_customer_id: stripeCustomerIdOf(sub) || null, stripe_subscription_id: sub.id, plan_ends_at: stripePeriodEndIso(sub) });
    }
  }
  if (!subId) {
    return res.status(404).json({ error: NO_SUBSCRIPTION_MESSAGE });
  }
  if (!sub) {
    const got = await stripeApiGet("/v1/subscriptions/" + encodeURIComponent(subId));
    if (!got.ok || !got.data || !got.data.id) {
      if (got.status === 404) return res.status(404).json({ error: NO_SUBSCRIPTION_MESSAGE });
      console.error("Stripe subscription lookup error:", got.status);
      return res.status(502).json({ error: "Cancellation couldn't be completed. Please try again." });
    }
    sub = got.data;
  }
  if (!sub.metadata || sub.metadata.user_id !== user.id) {
    return res.status(404).json({ error: NO_SUBSCRIPTION_MESSAGE });
  }
  if (sub.status === "canceled") {
    return res.json({ cancelled: true, alreadyCancelled: true, planEndsAt: null });
  }
  if (sub.cancel_at_period_end) {
    return res.json({ cancelled: true, alreadyCancelled: true, planEndsAt: stripePeriodEndIso(sub) || null });
  }
  if (sub.status !== "active" && sub.status !== "trialing") {
    return res.status(404).json({ error: NO_SUBSCRIPTION_MESSAGE });
  }
  const result = await stripeApiPost("/v1/subscriptions/" + encodeURIComponent(subId), { cancel_at_period_end: "true" });
  if (!result.ok || !result.data || !result.data.id) {
    console.error("Stripe cancel error:", result.status, result.data && result.data.error ? result.data.error.message : "no response");
    return res.status(502).json({ error: "Cancellation couldn't be completed. Please try again." });
  }
  const endsAt = stripePeriodEndIso(result.data) || null;
  /* Best effort: record the end date now so the site shows "Pro until
     <date>" straight away. The webhook's subscription.updated event
     confirms the same thing a moment later, so a failure here is not
     fatal — the cancel itself already happened at Stripe. */
  await supabaseAdminUpsertProfileFields(user.id, { plan_ends_at: endsAt });
  return res.json({ cancelled: true, alreadyCancelled: false, planEndsAt: endsAt });
});

/* ---------- Batch 3 money: Free/Pro daily limit (signed-in users only) ----------
   Free: signed-in users get 10 checks a day. Guests cannot be counted
   server-side (no identity), so guests are limited only in the frontend
   (5 a day, from localStorage history) — see index.html.
   Pro: unlimited. The plan is read from the profiles row only if it has
   a "plan" column; there is no such column today, so the plan lookup
   fails and everyone is treated as Free. A future migration adds the
   column and this code starts honouring it with no change.
   Counting: today's history rows for that user, via Supabase REST with
   the service-role key already on Render (same env vars as
   /delete-account). Fail open, always: if the token cannot be checked,
   the plan cannot be read, or the count cannot be read, the check runs
   — a lookup failure must never block a real user. The limit is checked
   BEFORE Turnstile, so a user at the limit never burns a Turnstile token.
   "Today" here is a UTC day; the frontend counts by the user's local
   day, so near midnight the two can differ by one check — the backend
   is the enforcer for signed-in users, the frontend is the friendly guide.
   No Stripe, no payments, no new dependency. */
/* ---------- Batch 4 quality+speed: identical-check cache ----------
   The same message + mode + tone + person + style asked twice within
   10 minutes gets the same result without a second OpenAI call — faster
   for the user and cheaper per check. Only successful results are cached,
   never errors or limit responses. The cache lives in memory only (up to
   100 entries, oldest dropped first), so a Render restart simply empties
   it — nothing is stored on disk and no user data leaves the server.
   The cache is checked AFTER the daily-limit check and AFTER Turnstile,
   so a user at their limit still gets the limit message, and the cache
   can never be used to skip verification. Response shape is unchanged. */
const ANALYZE_CACHE_TTL_MS = 10 * 60 * 1000;
const ANALYZE_CACHE_MAX = 100;
const analyzeCache = new Map();
function analyzeCacheKey(parts) {
  return crypto.createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}
function analyzeCacheGet(key) {
  const hit = analyzeCache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > ANALYZE_CACHE_TTL_MS) { analyzeCache.delete(key); return null; }
  return hit.data;
}
function analyzeCacheSet(key, data) {
  if (analyzeCache.size >= ANALYZE_CACHE_MAX) analyzeCache.delete(analyzeCache.keys().next().value);
  analyzeCache.set(key, { at: Date.now(), data: data });
}
const FREE_SIGNED_IN_DAILY_LIMIT = 10;
const BYS_LIMIT_CODE = "daily_limit";
function isProPlan(plan) { return plan === "pro"; }
function todayRangeUTC(now) {
  const d = new Date(now);
  const start = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const end = new Date(start); end.setUTCDate(end.getUTCDate() + 1);
  return { start: start.toISOString(), end: end.toISOString() };
}
function limitErrorBody(limit, used) {
  return {
    error: "You've used all " + limit + " of your free checks for today. Pro removes the limit \u2014 upgrade in Your account. Your checks start again tomorrow.",
    code: BYS_LIMIT_CODE, plan: "free", limit: limit, used: used,
  };
}
async function supabaseCountToday(userId) {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!key) return null; /* fail open: no key, no enforcement */
  const range = todayRangeUTC(new Date());
  try {
    const res = await fetch(SUPABASE_URL + "/rest/v1/history?select=id&user_id=eq." + encodeURIComponent(userId) + "&created_at=gte." + encodeURIComponent(range.start) + "&created_at=lt." + encodeURIComponent(range.end) + "&limit=" + (FREE_SIGNED_IN_DAILY_LIMIT + 1), {
      headers: { apikey: key, Authorization: "Bearer " + key, Prefer: "count=exact" },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null; /* fail open */
    const rows = await res.json();
    return Array.isArray(rows) ? rows.length : null;
  } catch (e) { return null; /* fail open: a lookup failure never blocks a check */ }
}
async function checkSignedInDailyLimit(req) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return { blocked: false, signedIn: false }; /* guest: frontend limit only */
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) return { blocked: false, signedIn: false }; /* fail open */
  const user = await getSupabaseUserFromToken(h.slice(7).trim());
  if (!user) return { blocked: false, signedIn: false }; /* fail open: bad token is already ignored by optionalAuth */
  /* Batch 4: the plan lookup and the today-count are independent, so
     they now run in parallel instead of one after the other — one fewer
     Supabase round trip before every signed-in check. Either failing
     still fails open (see below); a Pro plan still skips the limit. */
  const [plan, used] = await Promise.all([
    (async () => {
      try {
        const planRes = await fetch(SUPABASE_URL + "/rest/v1/profiles?select=plan&id=eq." + encodeURIComponent(user.id), {
          headers: { apikey: process.env.SUPABASE_SERVICE_ROLE_KEY, Authorization: "Bearer " + process.env.SUPABASE_SERVICE_ROLE_KEY },
          signal: AbortSignal.timeout(5000),
        });
        if (!planRes.ok) return null; /* no plan column yet — treat as Free */
        const rows = await planRes.json();
        return Array.isArray(rows) && rows[0] ? rows[0].plan : null;
      } catch (e) { return null; /* fail open */ }
    })(),
    supabaseCountToday(user.id),
  ]);
  if (isProPlan(plan)) return { blocked: false, signedIn: true };
  if (used === null) return { blocked: false, signedIn: true }; /* fail open */
  if (used >= FREE_SIGNED_IN_DAILY_LIMIT) return { blocked: true, body: limitErrorBody(FREE_SIGNED_IN_DAILY_LIMIT, used), signedIn: true };
  return { blocked: false, signedIn: true };
}
/* ---------- Sprint 2 fix pass: guest hourly limit on the analyse endpoints ----------
   Unauthenticated users (no valid Supabase token — checkSignedInDailyLimit
   above is the same check the daily limit uses, so no second token lookup)
   get max 5 analyse requests per hour per IP, on top of the existing
   10/min shared limiter and the 20/15min limiter. Signed-in users are
   exempt — their existing daily limits (Free 10/day, Pro unlimited)
   still apply. The count only moves for requests that pass validation
   and the daily-limit check, so a typo or a bad lane never burns a guest
   check. In-memory only (a Render restart empties it); the friendly 429
   names no internals. */
const GUEST_ANALYZE_HOURLY_LIMIT = 5;
const guestAnalyzeCounts = new Map();
function guestAnalyzeAllowed(req) {
  const ip = (req && req.ip) || "unknown";
  const now = Date.now();
  if (guestAnalyzeCounts.size > 1000) {
    guestAnalyzeCounts.forEach(function (entry, key) { if (now >= entry.resetAt) guestAnalyzeCounts.delete(key); });
  }
  let entry = guestAnalyzeCounts.get(ip);
  if (!entry || now >= entry.resetAt) { entry = { count: 0, resetAt: now + 60 * 60 * 1000 }; guestAnalyzeCounts.set(ip, entry); }
  if (entry.count >= GUEST_ANALYZE_HOURLY_LIMIT) return false;
  entry.count += 1;
  return true;
}
const GUEST_HOURLY_LIMIT_MESSAGE = "You've used your 5 guest checks for this hour. Sign in for 10 free checks a day, or try again in an hour.";
app.use("/analyze", optionalAuth);
app.use("/analyze", limiter);

app.post("/analyze", analyzeLimiter, async (req, res) => {
  try {
    const { message, mode, turnstileToken, replyMode, toneProfile, style, context, goal, draft } = req.body;
    const safeToneProfile = sanitiseToneProfile(toneProfile); // Phase 0: optional, ignored if missing/invalid
    const safeStyle = sanitiseStyle(style); // Phase 1 contexts+styles: optional, ignored if missing/invalid
    const safeContext = sanitiseContext(context); // Phase 1 contexts+styles: optional, ignored if missing/invalid
    const safeGoal = sanitiseGoal(goal); // Sprint 1: optional exact outcome/goal (max 200 chars), empty -> null
    const safeDraft = sanitiseDraft(draft); // Sprint 1: optional drafted reply to grade (max 1000 chars), empty -> null

    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Message is required." });
    }
    if (message.trim().length > 1000) {
      return res.status(400).json({ error: "Message is too long. Please keep it under 1000 characters." });
    }

    if (!mode || !["career", "negotiation", "high_conflict", "boundaries"].includes(mode)) {
      return res.status(400).json({ error: "Valid mode is required." });
    }

    /* Batch 3 money: signed-in daily limit, checked before Turnstile so a user at the limit never burns a token. Fail open — see checkSignedInDailyLimit. */
    const limitCheck = await checkSignedInDailyLimit(req);
    if (limitCheck.blocked) {
      return res.status(429).json(limitCheck.body);
    }
    /* Sprint 2 fix pass: guests get 5 analyse requests an hour per IP (guestAnalyzeAllowed above). Signed-in users are exempt. */
    if (!limitCheck.signedIn && !guestAnalyzeAllowed(req)) {
      return res.status(429).json({ error: GUEST_HOURLY_LIMIT_MESSAGE });
    }

  if (!turnstileToken || !String(turnstileToken).trim()) {
  return res.status(400).json({ error: "Verification is required." });
}
    if (!process.env.TURNSTILE_SECRET_KEY) {
      return res.status(500).json({ error: "Server verification is not configured." });
    }
    const formData = new URLSearchParams();
    formData.append("secret", process.env.TURNSTILE_SECRET_KEY);
    formData.append("response", turnstileToken);

    const turnstileResponse = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: formData,
      signal: AbortSignal.timeout(10000), /* Batch 4: never hang on verification */
    });

    const turnstileResult = await turnstileResponse.json();

    if (!turnstileResult.success) {
      return res.status(403).json({ error: "Verification failed. Please try again." });
    }

    if (!process.env.OPENAI_API_KEY) {
      return res.status(500).json({ error: "AI service is not configured." });
    }

    /* Batch 4: identical check within 10 minutes — serve the cached result instead of a second AI call. */
    const cacheKey = analyzeCacheKey({ message: message.trim(), mode, replyMode: Boolean(replyMode), toneProfile: safeToneProfile, style: safeStyle, context: safeContext, goal: safeGoal, draft: safeDraft });
    const cached = analyzeCacheGet(cacheKey);
    if (cached) return res.json(cached);

    const response = await client.chat.completions.create({
      model: "gpt-5.4-nano",
      response_format: { type: "json_object" },
      temperature: 0.7, /* Batch 4: was 0.8 — slightly steadier scores and JSON, same model */
      messages: [
       { role: "system", content: replyMode ? buildReplyPrompt(mode, safeToneProfile, safeStyle, safeContext, safeGoal, safeDraft) : buildSystemPrompt(mode, safeToneProfile, safeStyle, safeContext, safeGoal, safeDraft) },
        {
          role: "user",
          content: `Analyze and improve this message:\n\n${message.trim()}`,
        },
      ],
    });

    const raw = response?.choices?.[0]?.message?.content;

    if (!raw) {
      return res.status(500).json({ error: "No result returned." });
    }

    let parsed;

    try {
      parsed = JSON.parse(raw);
    } catch (parseError) {
      console.error("JSON parse error:", parseError.message);
      return res.status(500).json({ error: "AI returned invalid JSON." });
    }

    const finalData = formatFallback(mode, message.trim(), parsed, Boolean(safeDraft));
    analyzeCacheSet(cacheKey, finalData);

    res.json(finalData);
  } catch (error) {
    console.error("OpenAI error:", error.message);
    res.status(500).json({
      error: error.message || "Something went wrong.",
    });
  }
});

/* ---------- Pivot 3: POST /rizz — Rizz Check ----------
   Same guards as /analyze: validate input, signed-in daily limit
   (a rizz check counts as one check), guest 5/hour, Turnstile, then
   the AI (MOCK_AI -> OpenAI gpt-5.4-nano, the same text model
   /analyze uses). No cache for rizz results. The response is the
   strict rizz shape, normalised by formatRizzResult: score, label,
   roast, signal, replies[2] (one smooth, one funny). Roasts stay
   light and funny, never cruel and never sexualised. */
const RIZZ_MAX_CHARS = 500;
const RIZZ_LABELS = [
  { max: 20, label: "Dry texter" },
  { max: 40, label: "Needs work" },
  { max: 60, label: "Mid but trying" },
  { max: 80, label: "Smooth" },
  { max: 100, label: "Certified smooth" },
];
function rizzLabelForScore(score) {
  const s = Math.min(100, Math.max(0, Math.round(Number(score) || 0)));
  for (let i = 0; i < RIZZ_LABELS.length; i++) if (s <= RIZZ_LABELS[i].max) return RIZZ_LABELS[i].label;
  return "Certified smooth";
}
function buildRizzPrompt(text) {
  return `You are BeforeYouSay Rizz Check — a playful Gen Z wingman that rates a DM or text before it gets sent.
Rate this message for rizz (charm, flirt game, smoothness):
---
${text}
---
Return valid JSON only in this exact structure:
{
  "score": 0-100,
  "label": "Dry texter | Needs work | Mid but trying | Smooth | Certified smooth",
  "roast": "string — one playful roast of the message, 1-2 lines",
  "signal": "string — one line on what the message actually signals to the other person",
  "replies": [
    { "style": "smooth", "text": "string — a smoother version of the same message, sendable as written" },
    { "style": "funny", "text": "string — a funnier version of the same message, sendable as written" }
  ]
}
Rules:
- Score honestly: a dry "hey" or one-word reply is 0-20; a confident, specific, playful opener with a question or a hook is 61-100.
- The roast is light and funny, never cruel. Never mock someone's looks, body, money, background, or identity. Nothing sexualised, no slurs.
- Both replies keep the user's intent and sound like a real person texting, not a movie pickup line. Keep each reply under 200 characters.
- Keep the roast and the signal short — this is a quick check, not an essay.`;
}
function buildMockRizzResult() {
  /* MOCK_AI canned sample — schema-valid, clearly a sample. */
  return {
    score: 72,
    label: "Smooth",
    roast: "Confident opener, zero follow-through — you peaked at 'hey' and then ran out of ideas.",
    signal: "Friendly and low-pressure, but it reads like a group chat message, not a DM.",
    replies: [
      { style: "smooth", text: "Hey — your playlist post caught my eye. What are you listening to right now?" },
      { style: "funny", text: "Okay be honest, how many drafts did 'hey' take you? Asking for a friend (it's me, I'm the friend)." },
    ],
  };
}
function formatRizzResult(data) {
  /* Normalise any provider answer into the strict rizz shape. The
     label is always recomputed from the score, so it can never
     disagree with it. A missing or invalid piece falls back to a
     safe neutral value, never a crash. */
  const score = Math.min(100, Math.max(0, Math.round(Number(data && data.score) || 0)));
  const roast = typeof data?.roast === "string" && data.roast.trim()
    ? data.roast.trim().slice(0, 280)
    : "No strong read on this one — it's giving neutral energy.";
  const signal = typeof data?.signal === "string" && data.signal.trim()
    ? data.signal.trim().slice(0, 280)
    : "It reads friendly, but it doesn't give the other person much to reply to.";
  const FALLBACK_REPLIES = {
    smooth: "Hey — saw your post and it made me smile. What are you up to this weekend?",
    funny: "Okay, I admit it, I stared at this text for five minutes before sending it. How's your day going?",
  };
  const given = Array.isArray(data && data.replies) ? data.replies : [];
  function pickReply(style, index) {
    const byStyle = given.find(function (r) { return r && r.style === style && typeof r.text === "string" && r.text.trim(); });
    const r = byStyle || given[index];
    const text = r && typeof r.text === "string" && r.text.trim() ? r.text.trim().slice(0, 280) : "";
    return text || FALLBACK_REPLIES[style];
  }
  return {
    score: score,
    label: rizzLabelForScore(score),
    roast: roast,
    signal: signal,
    replies: [
      { style: "smooth", text: pickReply("smooth", 0) },
      { style: "funny", text: pickReply("funny", 1) },
    ],
  };
}
app.use("/rizz", optionalAuth);
app.use("/rizz", limiter);
app.post("/rizz", analyzeLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const text = typeof body.text === "string" ? body.text.trim() : "";
    if (!text) return res.status(400).json({ error: "Paste a DM or text to check first." });
    if (text.length > RIZZ_MAX_CHARS) {
      return res.status(400).json({ error: "Keep it under 500 characters — paste the message, not the whole chat." });
    }
    const limitCheck = await checkSignedInDailyLimit(req);
    if (limitCheck.blocked) return res.status(429).json(limitCheck.body);
    if (!limitCheck.signedIn && !guestAnalyzeAllowed(req)) {
      return res.status(429).json({ error: GUEST_HOURLY_LIMIT_MESSAGE });
    }
    const turnstile = await verifyTurnstile(req);
    if (turnstile) return res.status(turnstile.status).json({ error: turnstile.error });
    if (process.env.MOCK_AI === "true") return res.json(formatRizzResult(buildMockRizzResult()));
    if (!client) return res.status(500).json({ error: "AI service is not configured." });
    let raw;
    try {
      const response = await client.chat.completions.create({
        model: OPENAI_TEXT_MODEL,
        response_format: { type: "json_object" },
        temperature: 0.8,
        messages: [
          { role: "system", content: buildRizzPrompt(text) },
          { role: "user", content: "Rate this DM:\n\n" + text },
        ],
      });
      raw = response && response.choices && response.choices[0] && response.choices[0].message ? response.choices[0].message.content : null;
    } catch (error) {
      if (error && error.status) console.error("Rizz provider error status:", error.status, error.message || "");
      else console.error("Rizz error:", error && error.message ? error.message : error);
      const mapped = mapVisionUpstreamError(error);
      return res.status(mapped.status).json({ error: mapped.error });
    }
    if (!raw) return res.status(500).json({ error: "No result returned." });
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (parseError) {
      console.error("JSON parse error:", parseError.message);
      return res.status(500).json({ error: "AI returned invalid JSON." });
    }
    return res.json(formatRizzResult(parsed));
  } catch (error) {
    if (error && error.status) console.error("Rizz provider error status:", error.status, error.message || "");
    else console.error("Rizz error:", error && error.message ? error.message : error);
    const mapped = mapVisionUpstreamError(error);
    return res.status(mapped.status).json({ error: mapped.error });
  }
});

/* ---------- Sprint 2: POST /analyze-thread ----------
   Same guards as /analyze: lane whitelist, signed-in daily limit (a
   thread counts as one check), Turnstile, 60s vision timeout, safe
   JSON parsing, full fallback object. Sprint 2 fix pass adds the guest
   5/hour per-IP limit (signed-in users exempt) and flexible vision
   providers (MOCK_AI → Gemini → OpenAI, see selectVisionProvider).
   No cache (see above). Images are Base64 in memory only — never
   written to disk, never stored, never logged. */
app.use("/analyze-thread", optionalAuth);
app.use("/analyze-thread", limiter);
app.post("/analyze-thread", analyzeLimiter, async (req, res) => {
  try {
    const { images, mode, goal, turnstileToken, toneProfile, context, draft } = req.body || {};
    const safeGoal = sanitiseGoal(goal); /* required for a thread */
    const safeDraft = sanitiseDraft(draft);
    const safeToneProfile = sanitiseToneProfile(toneProfile);
    const safeContext = sanitiseContext(context);
    if (!safeGoal) {
      return res.status(400).json({ error: "What is your exact goal here? Add your goal to analyse a screenshot thread." });
    }
    if (!mode || !["career", "negotiation", "high_conflict", "boundaries"].includes(mode)) {
      return res.status(400).json({ error: "Valid mode is required." });
    }
    const checked = sanitiseThreadImages(images);
    if (checked.error) return res.status(checked.status).json({ error: checked.error });
    const safeImages = checked.images;
    const limitCheck = await checkSignedInDailyLimit(req);
    if (limitCheck.blocked) return res.status(429).json(limitCheck.body);
    /* Sprint 2 fix pass: guests get 5 analyse requests an hour per IP (guestAnalyzeAllowed above). Signed-in users are exempt. */
    if (!limitCheck.signedIn && !guestAnalyzeAllowed(req)) {
      return res.status(429).json({ error: GUEST_HOURLY_LIMIT_MESSAGE });
    }
    if (!turnstileToken || !String(turnstileToken).trim()) {
      return res.status(400).json({ error: "Verification is required." });
    }
    if (!process.env.TURNSTILE_SECRET_KEY) {
      return res.status(500).json({ error: "Server verification is not configured." });
    }
    const formData = new URLSearchParams();
    formData.append("secret", process.env.TURNSTILE_SECRET_KEY);
    formData.append("response", turnstileToken);
    const turnstileResponse = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: formData,
      signal: AbortSignal.timeout(10000),
    });
    const turnstileResult = await turnstileResponse.json();
    if (!turnstileResult.success) {
      return res.status(403).json({ error: "Verification failed. Please try again." });
    }
    /* Sprint 2 fix pass: provider selection (mock → Gemini → OpenAI).
       MOCK_AI is local testing only — never set it on Render. */
    const visionProvider = selectVisionProvider();
    if (visionProvider.provider === "none") {
      return res.status(500).json({ error: "AI service is not configured." });
    }
    const threadPrompt = buildThreadPrompt(mode, safeToneProfile, safeContext, safeGoal, safeDraft);
    let raw = null;
    if (visionProvider.provider === "mock") {
      raw = JSON.stringify(buildMockThreadResult(mode, safeImages.length, safeGoal, Boolean(safeDraft)));
    } else if (visionProvider.provider === "gemini") {
      raw = await callGeminiVision(threadPrompt + "\nRead these " + safeImages.length + " screenshots in order as one chronological thread and analyse them against the user's goal.", safeImages);
    } else {
      if (!client) {
        return res.status(500).json({ error: "AI service is not configured." });
      }
      const userContent = [
        { type: "text", text: "Read these " + safeImages.length + " screenshots in order as one chronological thread and analyse them against the user's goal." },
      ];
      safeImages.forEach(function (url) { userContent.push({ type: "image_url", image_url: { url: url } }); });
      const response = await client.chat.completions.create({
        model: visionProvider.model,
        response_format: { type: "json_object" },
        temperature: 0.7,
        messages: [
          { role: "system", content: threadPrompt },
          { role: "user", content: userContent },
        ],
      });
      raw = response?.choices?.[0]?.message?.content;
    }
    if (!raw) return res.status(500).json({ error: "No result returned." });
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (parseError) {
      console.error("JSON parse error:", parseError.message);
      return res.status(500).json({ error: "AI returned invalid JSON." });
    }
    const finalData = formatThreadFallback(mode, safeImages.length, parsed, Boolean(safeDraft), safeGoal);
    res.json(finalData);
  } catch (error) {
    /* Sprint 2 fix pass: never leak a raw provider error — log only the
       status (never the message, which can carry provider details) and
       answer with the generic friendly error from mapVisionUpstreamError. */
    if (error && error.status) console.error("Thread vision provider error status:", error.status);
    else console.error("Thread analysis error");
    const mapped = mapVisionUpstreamError(error);
    res.status(mapped.status).json({ error: mapped.error });
  }
});

/* ---------- B2B HR & Policy Compliance Firewall V1 ----------
   POST /vault/upload, GET /vault/list, POST /vault/delete,
   POST /hr-guardrail, POST /hr-audit.
   Australian small businesses (10-150 staff, no in-house lawyer).
   Jurisdiction: Australia only — Fair Work Act 2009 + the National
   Employment Standards (NES). US/UK are Coming Soon, not supported.
   No supabase-js: Supabase is reached with plain fetch + the
   service-role key, the same way /delete-account does it. No Stripe
   changes. No cache for HR results. MOCK_AI is local testing only —
   never set it on Render. Vault documents ARE stored (they have to
   be, to be checked against); screenshots were never stored. */
const OPENAI_TEXT_MODEL = "gpt-5.4-nano"; /* same text model as /analyze */
const GEMINI_TEXT_MODEL = GEMINI_VISION_MODEL; /* gemini-3.8-flash, text call */
const HR_SCENARIOS = ["performance", "leave", "termination", "contractor"];
const HR_SCENARIO_LABELS = {
  performance: "Performance & Warnings",
  leave: "Leave & Roster Changes",
  termination: "Termination & Redundancy",
  contractor: "Contractor & Client Scope",
};
const VAULT_DOC_TYPES = ["handbook", "contract", "policy", "other"];
const VAULT_MIMES = [
  "application/pdf",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "text/plain",
];
const VAULT_MAX_DOCS = 10;
const VAULT_MAX_FILE_BYTES = 10 * 1024 * 1024; /* 10MB decoded per file */
const VAULT_CONTEXT_MAX_CHARS = 60000; /* vault text passed to the AI, newest first */
const HR_AUDIT_MAX_TEXT_CHARS = 20000;
const HR_GUARDRAIL_MAX_DRAFT_CHARS = 5000;
const VAULT_AUTH_ERROR = "Sign in to upload company documents.";
const VAULT_NOT_SETUP_ERROR = "Company Vault isn't set up yet — the database table is still to be created. Ask the site owner to run the migration.";
const VAULT_FILE_TOO_LARGE_ERROR = "That file is too large — 10MB max per document.";
const VAULT_FULL_ERROR = "Your Company Vault is full (10 documents max).";

/* NES + unfair dismissal baselines (Fair Work Act 2009, Part 2-2 NES;
   Fair Work Ombudsman "Notice of termination & redundancy pay" fact
   sheet; Redfern Legal Centre "Unfair dismissal" factsheet, 30 Oct 2025).
   Verified 21 Nov 2026 — these numbers are the baselines, do not invent
   others. Passed to the AI as prompt context, not as a guarantee. */
const NES_BASELINES = `
Australian Fair Work baselines (Fair Work Act 2009, National Employment Standards, Part 2-2):
- Maximum weekly hours: 38 hours/week for full-time employees, plus reasonable additional hours.
- Annual leave: 4 weeks' paid leave per year (5 weeks for certain shiftworkers), pro rata for part-time.
- Personal/carer's leave: 10 days' paid leave per year (pro rata); compassionate leave: 2 days' paid leave per permissible occasion; 2 days' unpaid carer's leave per permissible occasion. Casuals get 2 days' unpaid carer's and 2 days' unpaid compassionate leave per occasion. Family and domestic violence leave is paid leave.
- Flexible working arrangements: eligible employees (12+ months' service, including parents/carers of school-age children, carers, people with disability, employees 55+, victims of family/domestic violence) may request flexible work; the employer must respond in writing within 21 days and may only refuse on reasonable business grounds.
- Parental leave: 12 months' unpaid leave (after 12 months' service), with a right to request an additional 12 months.
- Long service leave: as provided by state/territory laws (commonly after 7-10 years' continuous service).
- Public holidays: paid day off if the employee would ordinarily work; the employer may make a reasonable request to work.
- Notice of termination: written notice of the day of termination is required. Minimum notice: 1 year or less = 1 week; more than 1-3 years = 2 weeks; more than 3-5 years = 3 weeks; more than 5 years = 4 weeks; plus 1 week if the employee is over 45 with at least 2 years' service. Payment in lieu at the full pay rate is allowed. No notice is required for casuals, fixed-term/seasonal employees, dismissal for serious misconduct, trainees (not apprentices), or daily/weekly hire in building/construction or meat industries.
- Redundancy pay: 4-16 weeks' base pay by length of service, only for employees with 12+ months' service, and only if the employer is NOT a small business (fewer than 15 employees are exempt from redundancy pay).
- Fair Work Information Statement: must be given to new employees before, or as soon as practicable after, they start. Casuals must also be given the Casual Employment Information Statement.
- Casual conversion: casuals can request conversion to permanent after 6 months (12 months for small business employers).
- Superannuation guarantee: 12% from 1 July 2025.
Unfair dismissal overlay (Fair Work Act 2009, Part 3-2):
- 21 days from the day the dismissal takes effect to lodge an application (Form F2) with the Fair Work Commission. Extensions are very hard to get.
- Minimum employment period: 6 months, or 12 months if the employer is a small business (fewer than 15 employees).
- Coverage: the employee must be covered by a modern award or enterprise agreement, OR earn below the high income threshold: $190,100 for dismissals on or after 1 July 2026.
- Test: the dismissal must not be harsh, unjust or unreasonable — a valid reason plus procedural fairness (employee told the reason, given a chance to respond, allowed a support person).
- Small Business Fair Dismissal Code (fewer than 15 employees): summary dismissal is allowed for serious misconduct; otherwise the employer must give a warning and a chance to improve, in writing. Complying with the Code is a defence to unfair dismissal.
- Remedies: reinstatement is the primary remedy; compensation is capped at the lesser of 26 weeks' pay and half the high income threshold ($95,050 for dismissals from 1 July 2026).
- Genuine redundancy is a defence (real operational reasons, proper consultation, no reasonable redeployment).
- General protections claims (for example dismissal for exercising a workplace right) have no minimum employment period and no income cap, and the same 21-day deadline applies.
`;

function selectHrProvider() {
  /* Same order as selectVisionProvider: MOCK_AI -> Gemini -> OpenAI.
     MOCK_AI is local testing only — never set it on Render. */
  if (process.env.MOCK_AI === "true") return { provider: "mock" };
  if (process.env.GEMINI_API_KEY) return { provider: "gemini", model: GEMINI_TEXT_MODEL };
  if (process.env.OPENAI_API_KEY) return { provider: "openai", model: OPENAI_TEXT_MODEL };
  return { provider: "none" };
}
async function callGeminiText(prompt) {
  /* Gemini text call via plain fetch — no new npm dependency. Same
     shape as callGeminiVision but text-only (no image parts). Throws
     an Error with a .status on HTTP failure so the route can map
     401/403/429 cleanly with mapVisionUpstreamError. */
  const res = await fetch("https://generativelanguage.googleapis.com/v1beta/models/" + GEMINI_TEXT_MODEL + ":generateContent?key=" + encodeURIComponent(process.env.GEMINI_API_KEY || ""), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { responseMimeType: "application/json", temperature: 0.7 } }),
    signal: AbortSignal.timeout(60000),
  });
  if (!res.ok) { const e = new Error("Gemini request failed"); e.status = res.status; throw e; }
  const data = await res.json().catch(function () { return null; });
  const text = data && data.candidates && data.candidates[0] && data.candidates[0].content && Array.isArray(data.candidates[0].content.parts)
    ? data.candidates[0].content.parts.map(function (p) { return typeof p.text === "string" ? p.text : ""; }).join("")
    : "";
  if (!text.trim()) throw new Error("Gemini returned no text");
  return text;
}
function buildMockGuardrailResult(scenario) {
  /* MOCK_AI canned samples — schema-valid, realistic, clearly samples.
     Termination MUST be High risk with the unfair dismissal trap. */
  const rewrites = {
    termination: {
      firm_formal: "Following our written warning of 12 November and the meeting on 18 November, your employment will end on 2 December 2026, with 2 weeks' notice paid at your full pay rate. You may bring a support person to a final meeting on 25 November to discuss this decision before it is finalised.",
      constructive_neutral: "I want to talk through the performance concerns we raised in writing on 12 November, and hear your side before any decision is made. Can we meet on 25 November, with a support person if you would like one?",
    },
    performance: {
      firm_formal: "This is a formal written warning about the missed deadlines on 3 and 10 November. The standard is delivery by the agreed date; please confirm by Friday how you will meet it. If there is no improvement in the next four weeks, further action may follow.",
      constructive_neutral: "I want to work through the recent missed deadlines with you and agree a plan to get back on track. Can we meet on Thursday to talk it through?",
    },
    leave: {
      firm_formal: "Your request for flexible working arrangements has been received. We will respond in writing within 21 days, and any refusal will be on reasonable business grounds only.",
      constructive_neutral: "Thanks for letting me know — I'll confirm your leave dates in writing by Friday so we can plan cover.",
    },
    contractor: {
      firm_formal: "To confirm scope in writing: this engagement covers the website rebuild only, for $4,500, due 15 December. Any extra work will be quoted separately before it starts.",
      constructive_neutral: "Just confirming the scope in writing so we are on the same page — the rebuild only, $4,500, due 15 December. Happy to quote anything extra separately.",
    },
  };
  const samples = {
    termination: {
      compliance_risk_level: "High",
      policy_and_fair_work_conflicts: [
        { clause: "Small Business Fair Dismissal Code — warning and chance to improve in writing before dismissal", source: "fair_work_act", detail: "The draft dismisses the employee on the spot with no prior written warning and no chance to improve, so the Code defence is not available." },
        { clause: "NES notice of termination — 2 weeks at 2 years' service", source: "fair_work_nes", detail: "The draft gives no notice period and no payment in lieu; at 2 years' service the minimum is 2 weeks' notice at the full pay rate." },
        { clause: "Unfair dismissal — valid reason plus procedural fairness", source: "fair_work_act", detail: "The employee was never told the reason in writing or given a chance to respond with a support person present." },
      ],
      legal_hr_trap_warning: "This reads as an on-the-spot dismissal with no prior written warning — the employee can lodge an unfair dismissal claim with the Fair Work Commission within 21 days of the dismissal taking effect.",
      rewrites: rewrites.termination,
    },
    performance: {
      compliance_risk_level: "Medium",
      policy_and_fair_work_conflicts: [
        { clause: "Unfair dismissal — valid reason plus procedural fairness", source: "fair_work_act", detail: "The warning names no specific incidents or dates and gives no clear standard to improve against, so it would be weak evidence if the matter later reaches the Fair Work Commission." },
      ],
      legal_hr_trap_warning: "A vague warning with no dates, no standard and no improvement period can be treated as if no warning was given at all.",
      rewrites: rewrites.performance,
    },
    leave: {
      compliance_risk_level: "Medium",
      policy_and_fair_work_conflicts: [
        { clause: "NES flexible working arrangements — written response within 21 days, refusal only on reasonable business grounds", source: "fair_work_nes", detail: "The draft refuses the request verbally with no written response and no business grounds, which the NES does not allow." },
      ],
      legal_hr_trap_warning: "Refusing a flexible work request without a written response within 21 days, on reasonable business grounds, breaches the NES.",
      rewrites: rewrites.leave,
    },
    contractor: {
      compliance_risk_level: "Low",
      policy_and_fair_work_conflicts: [
        { clause: "Contractor scope must be confirmed in writing", source: "company_policy", detail: "The draft agrees extra work in a chat message with no written scope, price or date, which invites a scope dispute later." },
      ],
      legal_hr_trap_warning: "Agreeing extra work without a written scope and price can turn a fixed-price engagement into an open-ended one.",
      rewrites: rewrites.contractor,
    },
  };
  return samples[scenario] || samples.performance;
}
function buildMockAuditResult() {
  /* MOCK_AI canned sample — schema-valid. Missing notice of
     termination clause + Fair Work Information Statement reference,
     one contradiction, one suggested rewrite. */
  return {
    missing_mandatory_clauses: [
      "Notice of termination clause",
      "Fair Work Information Statement reference",
    ],
    contradictions_with_existing_policy: [
      { clause: "Probation period of 12 months", vault_source: "Employee Handbook.pdf", detail: "The contract states a 12-month probation period, but the vault handbook caps probation at 6 months." },
    ],
    suggested_clause_rewrites: [
      { original: "Notice of termination clause (missing)", rewrite: "Either party may terminate this employment by giving written notice: 1 week for service of 1 year or less, 2 weeks for more than 1 to 3 years, 3 weeks for more than 3 to 5 years, and 4 weeks for more than 5 years, plus 1 week if the employee is over 45 with at least 2 years' service, or payment in lieu at the full pay rate.", reason: "NES 9 (Fair Work Act 2009, Part 2-2) sets these minimum notice periods; a contract with no notice clause leaves the business exposed to an underpayment or unfair dismissal claim." },
    ],
  };
}
function formatGuardrailResult(data) {
  /* Normalise any provider answer into the strict guardrail shape —
     exactly the contract fields, nothing extra. A missing or invalid
     piece falls back to a safe neutral value, never a crash. */
  const levels = ["Low", "Medium", "High"];
  const risk = levels.includes(data && data.compliance_risk_level) ? data.compliance_risk_level : "Medium";
  const sources = ["company_policy", "fair_work_nes", "fair_work_act"];
  const conflicts = Array.isArray(data && data.policy_and_fair_work_conflicts)
    ? data.policy_and_fair_work_conflicts.map(function (c) {
        return {
          clause: typeof c.clause === "string" && c.clause.trim() ? c.clause.trim() : "Unspecified compliance issue",
          source: sources.includes(c.source) ? c.source : "fair_work_nes",
          detail: typeof c.detail === "string" && c.detail.trim() ? c.detail.trim() : "",
        };
      })
    : [];
  const trap = typeof data?.legal_hr_trap_warning === "string" && data.legal_hr_trap_warning.trim()
    ? data.legal_hr_trap_warning.trim()
    : "Check this against your company policy and the Fair Work baselines before sending.";
  const rewrites = data && data.rewrites && typeof data.rewrites === "object" ? data.rewrites : {};
  return {
    compliance_risk_level: risk,
    policy_and_fair_work_conflicts: conflicts,
    legal_hr_trap_warning: trap,
    rewrites: {
      firm_formal: typeof rewrites.firm_formal === "string" && rewrites.firm_formal.trim() ? rewrites.firm_formal.trim() : "",
      constructive_neutral: typeof rewrites.constructive_neutral === "string" && rewrites.constructive_neutral.trim() ? rewrites.constructive_neutral.trim() : "",
    },
  };
}
function formatAuditResult(data) {
  const missing = Array.isArray(data && data.missing_mandatory_clauses)
    ? data.missing_mandatory_clauses.filter(function (c) { return typeof c === "string" && c.trim(); }).map(function (c) { return c.trim(); })
    : [];
  const contradictions = Array.isArray(data && data.contradictions_with_existing_policy)
    ? data.contradictions_with_existing_policy.map(function (c) {
        return {
          clause: typeof c.clause === "string" && c.clause.trim() ? c.clause.trim() : "Unspecified clause",
          vault_source: typeof c.vault_source === "string" && c.vault_source.trim() ? c.vault_source.trim() : "",
          detail: typeof c.detail === "string" && c.detail.trim() ? c.detail.trim() : "",
        };
      })
    : [];
  const rewrites = Array.isArray(data && data.suggested_clause_rewrites)
    ? data.suggested_clause_rewrites.map(function (r) {
        return {
          original: typeof r.original === "string" && r.original.trim() ? r.original.trim() : "",
          rewrite: typeof r.rewrite === "string" && r.rewrite.trim() ? r.rewrite.trim() : "",
          reason: typeof r.reason === "string" && r.reason.trim() ? r.reason.trim() : "",
        };
      })
    : [];
  return { missing_mandatory_clauses: missing, contradictions_with_existing_policy: contradictions, suggested_clause_rewrites: rewrites };
}
function buildGuardrailPrompt(draft, scenario, vaultContext) {
  return `You are BeforeYouSay HR Guardrail, an Australian HR compliance checker for small businesses.
Jurisdiction: Australia — Fair Work Act 2009 and the National Employment Standards (NES). Do not apply any other country's law.
Scenario: ${HR_SCENARIO_LABELS[scenario] || scenario}.
Draft message to check before sending:
---
${draft}
---
Company policies (newest first; these are the employer's own rules — a conflict with them is a conflict even if the law allows it):
${vaultContext || "No company documents uploaded — check against the Fair Work baselines only."}
${NES_BASELINES}
Return valid JSON only in this exact structure:
{
  "compliance_risk_level": "Low | Medium | High",
  "policy_and_fair_work_conflicts": [
    { "clause": "string — the exact clause/rule violated", "source": "company_policy | fair_work_nes | fair_work_act", "detail": "string — what the draft does wrong" }
  ],
  "legal_hr_trap_warning": "string — the single biggest trap, 1-2 sentences",
  "rewrites": { "firm_formal": "string — a firm, formal rewrite of the draft", "constructive_neutral": "string — a constructive, neutral rewrite of the draft" }
}
Rules:
- Judge risk honestly: an on-the-spot dismissal with no warning is High; a vague warning or a refused leave request with no written grounds is Medium; a clean, documented message is Low.
- Name the exact clause or NES rule in each conflict; never invent a clause number or a dollar figure that is not in the baselines above.
- The trap warning must be the single biggest risk, in 1-2 sentences.
- Both rewrites must keep the manager's intent but remove the compliance risk; keep them sendable as written.
- This is operational policy alignment only, not formal legal advice — do not present it as legal advice.`;
}
function buildAuditPrompt(documentText, vaultContext) {
  return `You are BeforeYouSay Contract & Policy Auditor, an Australian HR compliance checker for small businesses.
Jurisdiction: Australia — Fair Work Act 2009 and the National Employment Standards (NES). Do not apply any other country's law.
Document to audit:
---
${documentText}
---
Company policies already on file (newest first; the document must not contradict them):
${vaultContext || "No company documents uploaded — check against the Fair Work baselines only."}
${NES_BASELINES}
Return valid JSON only in this exact structure:
{
  "missing_mandatory_clauses": ["string — each a clause the document must have but doesn't"],
  "contradictions_with_existing_policy": [
    { "clause": "string", "vault_source": "string — file_name of the vault doc", "detail": "string" }
  ],
  "suggested_clause_rewrites": [
    { "original": "string — the offending wording (or the missing clause name)", "rewrite": "string — compliant replacement wording", "reason": "string — why, citing the NES/policy rule" }
  ]
}
Rules:
- A contract must have, at minimum: position and duties, employment type and hours (38 hours/week for full-time), pay, leave per the NES, probation, notice of termination per the NES, and a Fair Work Information Statement reference. Flag each one that is missing.
- Only list a contradiction when the document genuinely conflicts with a vault document — never invent a vault document.
- Never invent a clause number, a dollar figure, or a leave amount that is not in the baselines above.
- This is operational policy alignment only, not formal legal advice — do not present it as legal advice.`;
}
async function verifyTurnstile(req) {
  /* Shared Turnstile check for the HR routes (same messages as
     /analyze). Returns null when verification passes, else
     { status, error } for the route to answer with. */
  const token = req.body && req.body.turnstileToken;
  if (!token || !String(token).trim()) return { status: 400, error: "Verification is required." };
  if (!process.env.TURNSTILE_SECRET_KEY) return { status: 500, error: "Server verification is not configured." };
  const formData = new URLSearchParams();
  formData.append("secret", process.env.TURNSTILE_SECRET_KEY);
  formData.append("response", String(token));
  const turnstileResponse = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: formData,
    signal: AbortSignal.timeout(10000),
  });
  const turnstileResult = await turnstileResponse.json().catch(function () { return null; });
  if (!turnstileResult || !turnstileResult.success) {
    const codes = turnstileResult && Array.isArray(turnstileResult["error-codes"]) ? turnstileResult["error-codes"].join(",") : "unknown";
    console.error("Turnstile verify failed:", codes);
    return { status: 403, error: "Verification failed. Please try again." };
  }
  return null;
}
async function requireVaultUser(req, res) {
  /* Vault auth: the token is checked by asking Supabase itself
     (getSupabaseUserFromToken), the same way /delete-account does it.
     optionalAuth is NOT used here — it silently ignores bad tokens
     when SUPABASE_JWT_SECRET is unset. */
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) { res.status(401).json({ error: VAULT_AUTH_ERROR }); return null; }
  const user = await getSupabaseUserFromToken(h.slice(7).trim());
  if (!user) { res.status(401).json({ error: VAULT_AUTH_ERROR }); return null; }
  return user;
}
function isTableMissingStatus(status, bodyText) {
  /* PostgREST answers table-not-found as 404 with code PGRST205. */
  return status === 404 || (typeof bodyText === "string" && bodyText.indexOf("PGRST205") !== -1);
}
async function supabaseVaultRequest(path, method, body) {
  const headers = {
    apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: "Bearer " + process.env.SUPABASE_SERVICE_ROLE_KEY,
    "Content-Type": "application/json",
  };
  const opts = { method: method, headers: headers, signal: AbortSignal.timeout(10000) };
  if (body !== undefined) opts.body = JSON.stringify(body);
  return fetch(SUPABASE_URL + path, opts);
}
async function extractDocumentText(mime, buffer) {
  /* Server-side text extraction for vault uploads and /hr-audit files.
     pdf-parse v2 is a class (new PDFParse({data}).getText()); the v1
     function call is kept as a fallback. mammoth extractRawText for
     DOCX. Plain text is returned as-is. Returns "" when nothing could
     be read — the route turns that into the friendly 400. */
  if (mime === "text/plain") return buffer.toString("utf8");
  if (mime === "application/pdf") {
    const pdfParse = require("pdf-parse");
    if (pdfParse && pdfParse.PDFParse) {
      const parser = new pdfParse.PDFParse({ data: buffer });
      try {
        const result = await parser.getText();
        if (result && typeof result.text === "string") return result.text;
        if (result && Array.isArray(result.pages)) return result.pages.map(function (p) { return p.text || ""; }).join("\n");
        return "";
      } finally {
        try { await parser.destroy(); } catch (e) { /* ignore */ }
      }
    }
    const data = await pdfParse(buffer);
    return (data && data.text) || "";
  }
  if (mime === "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
    const mammoth = require("mammoth");
    const result = await mammoth.extractRawText({ buffer: buffer });
    return (result && result.value) || "";
  }
  return "";
}
async function loadVaultContext(userId) {
  /* Loads the caller's vault docs (newest first) for the AI prompt,
     truncated to VAULT_CONTEXT_MAX_CHARS in total. Fail-open: a
     missing table or any load failure means NES baselines only — it
     must never fail the check itself. Returns { context, tableMissing }. */
  if (!userId || !process.env.SUPABASE_SERVICE_ROLE_KEY) return { context: "", tableMissing: false };
  try {
    const res = await supabaseVaultRequest("/rest/v1/company_policies?select=file_name,extracted_text&user_id=eq." + encodeURIComponent(userId) + "&order=created_at.desc&limit=" + VAULT_MAX_DOCS, "GET");
    if (!res.ok) {
      let bodyText = "";
      try { bodyText = await res.text(); } catch (e) { bodyText = ""; }
      return { context: "", tableMissing: isTableMissingStatus(res.status, bodyText) };
    }
    const rows = await res.json().catch(function () { return null; });
    if (!Array.isArray(rows)) return { context: "", tableMissing: false };
    let used = 0;
    const parts = [];
    for (let i = 0; i < rows.length; i++) {
      const text = typeof rows[i].extracted_text === "string" ? rows[i].extracted_text : "";
      if (!text.trim()) continue;
      const remaining = VAULT_CONTEXT_MAX_CHARS - used;
      if (remaining <= 0) break;
      const chunk = text.slice(0, remaining);
      parts.push("--- " + (rows[i].file_name || "document") + " ---\n" + chunk);
      used += chunk.length;
    }
    return { context: parts.join("\n\n"), tableMissing: false };
  } catch (e) { return { context: "", tableMissing: false }; }
}
async function getSignedInUserId(req) {
  /* Best-effort caller id for vault loading on the HR routes (guests
     have no vault). Fails open to null — a bad token is already
     ignored by the limit checks. */
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return null;
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) return null;
  const user = await getSupabaseUserFromToken(h.slice(7).trim());
  return user ? user.id : null;
}
async function runHrProvider(provider, prompt, userText) {
  /* Runs one HR prompt through the selected provider and returns the
     raw JSON text. Throws an Error with .status for upstream failures
     so the route maps it with mapVisionUpstreamError. */
  if (provider.provider === "gemini") {
    try {
      return await callGeminiText(prompt + "\n\n" + userText);
    } catch (geminiError) {
      console.error("HR Gemini failed, falling back to OpenAI:", geminiError && geminiError.message ? geminiError.message : geminiError);
      if (!client) throw geminiError;
      provider = { provider: "openai", model: OPENAI_TEXT_MODEL };
    }
  }
  if (!client) throw Object.assign(new Error("AI service is not configured"), { status: 0 });
  const response = await client.chat.completions.create({
    model: OPENAI_TEXT_MODEL,
    response_format: { type: "json_object" },
    temperature: 0.7,
    messages: [
      { role: "system", content: prompt },
      { role: "user", content: userText },
    ],
  });
  const raw = response && response.choices && response.choices[0] && response.choices[0].message ? response.choices[0].message.content : null;
  if (!raw) throw new Error("No result returned");
  return raw;
}

/* ---------- Company Vault ---------- */
app.post("/vault/upload", async (req, res) => {
  try {
    const user = await requireVaultUser(req, res);
    if (!user) return; /* 401 already sent */
    if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(503).json({ error: VAULT_NOT_SETUP_ERROR });
    }
    const body = req.body || {};
    const fileName = typeof body.file_name === "string" ? body.file_name.trim().slice(0, 200) : "";
    if (!fileName) return res.status(400).json({ error: "Add a file name to upload a document." });
    if (!VAULT_DOC_TYPES.includes(body.doc_type)) {
      return res.status(400).json({ error: "Choose a document type: handbook, contract, policy or other." });
    }
    if (!VAULT_MIMES.includes(body.mime)) {
      return res.status(400).json({ error: "Only PDF, DOCX or plain text documents can be uploaded." });
    }
    if (typeof body.data_base64 !== "string" || !body.data_base64.trim()) {
      return res.status(400).json({ error: "Add a file to upload." });
    }
    const buffer = Buffer.from(body.data_base64, "base64");
    if (!buffer.length) return res.status(400).json({ error: "We couldn't read that file." });
    if (buffer.length > VAULT_MAX_FILE_BYTES) {
      return res.status(413).json({ error: VAULT_FILE_TOO_LARGE_ERROR });
    }
    let text = "";
    try { text = await extractDocumentText(body.mime, buffer); } catch (e) { text = ""; }
    if (!text || !text.trim()) {
      return res.status(400).json({ error: "We couldn't read any text from that file." });
    }
    text = text.trim();
    /* Max 10 documents per user — count first, then insert. */
    const countRes = await supabaseVaultRequest("/rest/v1/company_policies?select=id&user_id=eq." + encodeURIComponent(user.id) + "&limit=" + (VAULT_MAX_DOCS + 1), "GET");
    if (!countRes.ok) {
      let bodyText = "";
      try { bodyText = await countRes.text(); } catch (e) { bodyText = ""; }
      if (isTableMissingStatus(countRes.status, bodyText)) return res.status(503).json({ error: VAULT_NOT_SETUP_ERROR });
      return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
    const existing = await countRes.json().catch(function () { return null; });
    if (Array.isArray(existing) && existing.length >= VAULT_MAX_DOCS) {
      return res.status(409).json({ error: VAULT_FULL_ERROR });
    }
    const insertRes = await fetch(SUPABASE_URL + "/rest/v1/company_policies", {
      method: "POST",
      headers: {
        apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: "Bearer " + process.env.SUPABASE_SERVICE_ROLE_KEY,
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify({ user_id: user.id, file_name: fileName, doc_type: body.doc_type, extracted_text: text }),
      signal: AbortSignal.timeout(10000),
    });
    if (!insertRes.ok) {
      let bodyText = "";
      try { bodyText = await insertRes.text(); } catch (e) { bodyText = ""; }
      if (isTableMissingStatus(insertRes.status, bodyText)) return res.status(503).json({ error: VAULT_NOT_SETUP_ERROR });
      console.error("Vault upload failed:", insertRes.status);
      return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
    const rows = await insertRes.json().catch(function () { return null; });
    const row = Array.isArray(rows) && rows[0] ? rows[0] : null;
    return res.json({
      id: row && row.id ? row.id : null,
      file_name: fileName,
      doc_type: body.doc_type,
      chars: text.length,
      created_at: row && row.created_at ? row.created_at : new Date().toISOString(),
    });
  } catch (e) {
    console.error("Vault upload error");
    return res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

app.get("/vault/list", async (req, res) => {
  try {
    const user = await requireVaultUser(req, res);
    if (!user) return; /* 401 already sent */
    if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(503).json({ error: VAULT_NOT_SETUP_ERROR });
    }
    const listRes = await supabaseVaultRequest("/rest/v1/company_policies?select=id,file_name,doc_type,created_at,extracted_text&user_id=eq." + encodeURIComponent(user.id) + "&order=created_at.desc&limit=" + VAULT_MAX_DOCS, "GET");
    if (!listRes.ok) {
      let bodyText = "";
      try { bodyText = await listRes.text(); } catch (e) { bodyText = ""; }
      if (isTableMissingStatus(listRes.status, bodyText)) return res.status(503).json({ error: VAULT_NOT_SETUP_ERROR });
      return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
    const rows = await listRes.json().catch(function () { return null; });
    const documents = (Array.isArray(rows) ? rows : []).map(function (r) {
      return {
        id: r.id,
        file_name: r.file_name,
        doc_type: r.doc_type,
        created_at: r.created_at,
        chars: typeof r.extracted_text === "string" ? r.extracted_text.length : 0,
      };
    });
    return res.json({ documents: documents });
  } catch (e) {
    console.error("Vault list error");
    return res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

app.post("/vault/delete", async (req, res) => {
  try {
    const user = await requireVaultUser(req, res);
    if (!user) return; /* 401 already sent */
    if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(503).json({ error: VAULT_NOT_SETUP_ERROR });
    }
    const id = req.body && typeof req.body.id === "string" ? req.body.id.trim() : "";
    if (!id) return res.status(400).json({ error: "Choose a document to delete." });
    /* Idempotent: an unknown id still answers { deleted: true }. The
       delete is scoped to id AND user_id, so nobody can delete
       another user's document. */
    const delRes = await supabaseVaultRequest("/rest/v1/company_policies?id=eq." + encodeURIComponent(id) + "&user_id=eq." + encodeURIComponent(user.id), "DELETE");
    if (!delRes.ok) {
      let bodyText = "";
      try { bodyText = await delRes.text(); } catch (e) { bodyText = ""; }
      if (isTableMissingStatus(delRes.status, bodyText)) return res.status(503).json({ error: VAULT_NOT_SETUP_ERROR });
    }
    return res.json({ deleted: true });
  } catch (e) {
    console.error("Vault delete error");
    return res.status(500).json({ error: "Something went wrong. Please try again." });
  }
});

/* ---------- HR Guardrail + Contract & Policy Auditor ----------
   Same guards as /analyze-thread: validate input, signed-in daily
   limit, guest 5/hour, Turnstile, then the provider (MOCK_AI ->
   Gemini -> OpenAI). No cache for HR results. */
app.use("/hr-guardrail", optionalAuth);
app.use("/hr-guardrail", limiter);
app.post("/hr-guardrail", analyzeLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const draft = typeof body.draft === "string" ? body.draft.trim() : "";
    if (!draft) return res.status(400).json({ error: "Add a draft to check." });
    if (draft.length > HR_GUARDRAIL_MAX_DRAFT_CHARS) {
      return res.status(400).json({ error: "That draft is too long. Please keep it under 5,000 characters." });
    }
    if (!HR_SCENARIOS.includes(body.scenario)) {
      return res.status(400).json({ error: "Choose a scenario: Performance & Warnings, Leave & Roster Changes, Termination & Redundancy, or Contractor & Client Scope." });
    }
    if (body.jurisdiction !== "australia") {
      return res.status(400).json({ error: "Australia is the only supported jurisdiction for now." });
    }
    const limitCheck = await checkSignedInDailyLimit(req);
    if (limitCheck.blocked) return res.status(429).json(limitCheck.body);
    if (!limitCheck.signedIn && !guestAnalyzeAllowed(req)) {
      return res.status(429).json({ error: GUEST_HOURLY_LIMIT_MESSAGE });
    }
    const turnstile = await verifyTurnstile(req);
    if (turnstile) return res.status(turnstile.status).json({ error: turnstile.error });
    const provider = selectHrProvider();
    if (provider.provider === "none") {
      return res.status(500).json({ error: "AI service is not configured." });
    }
    if (provider.provider === "mock") {
      return res.json(formatGuardrailResult(buildMockGuardrailResult(body.scenario)));
    }
    const userId = await getSignedInUserId(req);
    const vault = await loadVaultContext(userId); /* fail-open: NES baselines only on failure */
    const prompt = buildGuardrailPrompt(draft, body.scenario, vault.context);
    let raw;
    try {
      raw = await runHrProvider(provider, prompt, "Draft to check:\n" + draft);
    } catch (error) {
      if (error && error.status) console.error("HR guardrail provider error status:", error.status, error.message || "");
      else console.error("HR guardrail error:", error && error.message ? error.message : error);
      const mapped = mapVisionUpstreamError(error);
      return res.status(mapped.status).json({ error: mapped.error });
    }
    if (!raw) return res.status(500).json({ error: "No result returned." });
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (parseError) {
      console.error("JSON parse error:", parseError.message);
      return res.status(500).json({ error: "AI returned invalid JSON." });
    }
    return res.json(formatGuardrailResult(parsed));
  } catch (error) {
    if (error && error.status) console.error("HR guardrail provider error status:", error.status, error.message || "");
    else console.error("HR guardrail error:", error && error.message ? error.message : error);
    const mapped = mapVisionUpstreamError(error);
    return res.status(mapped.status).json({ error: mapped.error });
  }
});

app.use("/hr-audit", optionalAuth);
app.use("/hr-audit", limiter);
app.post("/hr-audit", analyzeLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    let documentText = "";
    if (typeof body.document_text === "string" && body.document_text.trim()) {
      documentText = body.document_text.trim();
      if (documentText.length > HR_AUDIT_MAX_TEXT_CHARS) {
        return res.status(400).json({ error: "That document is too long. Please keep it under 20,000 characters." });
      }
    } else if (body.file && typeof body.file === "object") {
      const file = body.file;
      if (!["application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"].includes(file.mime)) {
        return res.status(400).json({ error: "Only PDF or DOCX files can be audited." });
      }
      if (typeof file.data_base64 !== "string" || !file.data_base64.trim()) {
        return res.status(400).json({ error: "Add a file to audit." });
      }
      const buffer = Buffer.from(file.data_base64, "base64");
      if (!buffer.length) return res.status(400).json({ error: "We couldn't read that file." });
      if (buffer.length > VAULT_MAX_FILE_BYTES) {
        return res.status(413).json({ error: VAULT_FILE_TOO_LARGE_ERROR });
      }
      try { documentText = (await extractDocumentText(file.mime, buffer) || "").trim(); } catch (e) { documentText = ""; }
      if (!documentText) {
        return res.status(400).json({ error: "We couldn't read any text from that file." });
      }
    } else {
      return res.status(400).json({ error: "Add the contract or policy text, or upload a PDF or DOCX file to audit." });
    }
    const limitCheck = await checkSignedInDailyLimit(req);
    if (limitCheck.blocked) return res.status(429).json(limitCheck.body);
    if (!limitCheck.signedIn && !guestAnalyzeAllowed(req)) {
      return res.status(429).json({ error: GUEST_HOURLY_LIMIT_MESSAGE });
    }
    const turnstile = await verifyTurnstile(req);
    if (turnstile) return res.status(turnstile.status).json({ error: turnstile.error });
    const provider = selectHrProvider();
    if (provider.provider === "none") {
      return res.status(500).json({ error: "AI service is not configured." });
    }
    if (provider.provider === "mock") {
      return res.json(formatAuditResult(buildMockAuditResult()));
    }
    const userId = await getSignedInUserId(req);
    const vault = await loadVaultContext(userId); /* fail-open: NES baselines only on failure */
    const prompt = buildAuditPrompt(documentText, vault.context);
    let raw;
    try {
      raw = await runHrProvider(provider, prompt, "Document to audit:\n" + documentText);
    } catch (error) {
      if (error && error.status) console.error("HR audit provider error status:", error.status, error.message || "");
      else console.error("HR audit error:", error && error.message ? error.message : error);
      const mapped = mapVisionUpstreamError(error);
      return res.status(mapped.status).json({ error: mapped.error });
    }
    if (!raw) return res.status(500).json({ error: "No result returned." });
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (parseError) {
      console.error("JSON parse error:", parseError.message);
      return res.status(500).json({ error: "AI returned invalid JSON." });
    }
    return res.json(formatAuditResult(parsed));
  } catch (error) {
    if (error && error.status) console.error("HR audit provider error status:", error.status, error.message || "");
    else console.error("HR audit error:", error && error.message ? error.message : error);
    const mapped = mapVisionUpstreamError(error);
    return res.status(mapped.status).json({ error: mapped.error });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
