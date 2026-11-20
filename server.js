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

app.use(express.json({ limit: "1mb" }));

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

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  timeout: 60000, /* Batch 4: a hung AI call fails after 60s instead of hanging forever */
});

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
  const mode = ["workplace", "relationship", "negotiation"].includes(input.defaultMode) ? input.defaultMode : null;
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

function buildSystemPrompt(mode, toneProfile, style, context) {
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
`;

  const modeGuidance = {
    workplace: `
Mode: Workplace
Optimize for professionalism, clarity, confidence, authority balance, concise wording, and low passive-aggression.
Avoid sounding weak, emotional, rude, or awkward.
`,
    relationship: `
Mode: Relationship
Optimize for empathy, honesty, calmness, emotional clarity, and de-escalation.
Avoid sounding cold, controlling, manipulative, reactive, or blaming.
`,
    negotiation: `
Mode: Negotiation
Optimize for leverage, clarity, assertiveness, persuasion, and calm confidence.
Avoid sounding needy, overexplaining, emotional, defensive, or weak.
`,
  };

  return `${commonRules}\n${modeGuidance[mode] || ""}${toneProfileText(toneProfile)}${contextText(context)}${styleText(style)}\n${outputFormat}`;
}

/* Batch 4: AI scores must be integers 1-10; a missing or out-of-range score falls back to 6, never 0 or 11. */
function clampScoreOut(v) {
  if (v === null || v === undefined || v === "") return 6; /* missing score */
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(10, Math.max(1, Math.round(n))) : 6;
}
function formatFallback(mode, message, data) {
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
    better_version: data?.better_version || message,
    softer_version: data?.softer_version || message,
    stronger_version: data?.stronger_version || message,
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

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: "Too many requests. Please wait a minute and try again." },
});
function buildReplyPrompt(mode, toneProfile, style, context) {
  const modeInstructions = {
    workplace: `You are helping someone reply professionally to a message they received at work. Replies must be calm, clear, and boundary-aware. No slang. Keep it respectful and concise.`,
    relationship: `You are helping someone reply in a relationship context to a message they received. Replies must be emotionally intelligent, honest, warm, and de-escalating. No blame or coldness.`,
    negotiation: `You are helping someone reply in a negotiation to a message they received. Replies must be assertive, strategic, and calm. Show leverage without desperation. Stay in control.`
  };

  return `
You are BeforeYouSay, an elite AI communication coach.

The user RECEIVED a message from someone else and needs help replying back.
Write 3 replies FROM the user, responding TO the sender of that message.

${modeInstructions[mode] || modeInstructions.workplace}

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
${toneProfileText(toneProfile)}${contextText(context)}${styleText(style)}
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
  if (!h.startsWith("Bearer ")) return { blocked: false }; /* guest: frontend limit only */
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) return { blocked: false }; /* fail open */
  const user = await getSupabaseUserFromToken(h.slice(7).trim());
  if (!user) return { blocked: false }; /* fail open: bad token is already ignored by optionalAuth */
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
  if (isProPlan(plan)) return { blocked: false };
  if (used === null) return { blocked: false }; /* fail open */
  if (used >= FREE_SIGNED_IN_DAILY_LIMIT) return { blocked: true, body: limitErrorBody(FREE_SIGNED_IN_DAILY_LIMIT, used) };
  return { blocked: false };
}
app.use("/analyze", optionalAuth);
app.use("/analyze", limiter);

app.post("/analyze", analyzeLimiter, async (req, res) => {
  try {
    const { message, mode, turnstileToken, replyMode, toneProfile, style, context } = req.body;
    const safeToneProfile = sanitiseToneProfile(toneProfile); // Phase 0: optional, ignored if missing/invalid
    const safeStyle = sanitiseStyle(style); // Phase 1 contexts+styles: optional, ignored if missing/invalid
    const safeContext = sanitiseContext(context); // Phase 1 contexts+styles: optional, ignored if missing/invalid

    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Message is required." });
    }
    if (message.trim().length > 1000) {
      return res.status(400).json({ error: "Message is too long. Please keep it under 1000 characters." });
    }

    if (!mode || !["workplace", "relationship", "negotiation"].includes(mode)) {
      return res.status(400).json({ error: "Valid mode is required." });
    }

    /* Batch 3 money: signed-in daily limit, checked before Turnstile so a user at the limit never burns a token. Fail open — see checkSignedInDailyLimit. */
    const limitCheck = await checkSignedInDailyLimit(req);
    if (limitCheck.blocked) {
      return res.status(429).json(limitCheck.body);
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
    const cacheKey = analyzeCacheKey({ message: message.trim(), mode, replyMode: Boolean(replyMode), toneProfile: safeToneProfile, style: safeStyle, context: safeContext });
    const cached = analyzeCacheGet(cacheKey);
    if (cached) return res.json(cached);

    const response = await client.chat.completions.create({
      model: "gpt-5.4-nano",
      response_format: { type: "json_object" },
      temperature: 0.7, /* Batch 4: was 0.8 — slightly steadier scores and JSON, same model */
      messages: [
       { role: "system", content: replyMode ? buildReplyPrompt(mode, safeToneProfile, safeStyle, safeContext) : buildSystemPrompt(mode, safeToneProfile, safeStyle, safeContext) },
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

    const finalData = formatFallback(mode, message.trim(), parsed);
    analyzeCacheSet(cacheKey, finalData);

    res.json(finalData);
  } catch (error) {
    console.error("OpenAI error:", error.message);
    res.status(500).json({
      error: error.message || "Something went wrong.",
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
