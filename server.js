const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const OpenAI = require("openai");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto"); // Phase 0: only used for optional Supabase JWT checks — no new dependency.
dotenv.config();

const app = express();

const analyzeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many requests. Please try again later." },
});
app.use(cors({
  origin: ["https://beforeyousay.com", "http://localhost:3000"],
  methods: ["GET", "POST"],
}));
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
  const mode = ["workplace", "relationship", "rizz", "negotiation"].includes(input.defaultMode) ? input.defaultMode : null;
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
- coach_note should be short and useful.
- why_it_might_land_badly should explain how the message may be perceived.
- If the message is already strong, still improve it slightly.
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
    rizz: `
Mode: Rizz
Optimize for charm, confidence, playfulness, smoothness, and attraction.
Avoid cringe, desperation, awkwardness, try-hard energy, or weird over-flirting.
`,
    negotiation: `
Mode: Negotiation
Optimize for leverage, clarity, assertiveness, persuasion, and calm confidence.
Avoid sounding needy, overexplaining, emotional, defensive, or weak.
`,
  };

  return `${commonRules}\n${modeGuidance[mode] || ""}${toneProfileText(toneProfile)}${contextText(context)}${styleText(style)}\n${outputFormat}`;
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
      clarity: Number(data?.scores?.clarity) || 6,
      confidence: Number(data?.scores?.confidence) || 6,
      emotional_control: Number(data?.scores?.emotional_control) || 6,
      effectiveness: Number(data?.scores?.effectiveness) || 6,
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
    rizz: `You are helping someone reply with rizz to a message they received. Replies must be smooth, playful, and slightly cocky without being desperate or cringe. Think: unbothered, funny, attractive energy. Never formal. Never "I respect that." Never "no worries." Keep it short and punchy.`,
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

- Received: "i have a boyfriend"
  ✅ Correct reply: "Respect. So coffee as friends then?"
  ❌ Wrong reply: "I have a boyfriend so I can't pursue anything further."

Return valid JSON only in this exact structure:
{
  "tone_detected": "string — the tone of the message they received",
  "why_it_might_land_badly": "string — what to watch out for when replying",
  "better_version": "string — the best balanced reply the user can send back",
  "softer_version": "string — a softer or warmer reply the user can send back",
  "stronger_version": "string — a more direct or assertive reply the user can send back",
  "coach_note": "string — one short tactical tip for this specific situation",
  "risk_level": "low",
  "should_send": "yes",
  "intent_guess": "string — what the sender likely meant",
  "original_message": "",
  "scores": { "clarity": 8, "confidence": 8, "emotional_control": 8, "effectiveness": 8 }
}

Rules:
- The user is the RECIPIENT. All 3 replies are what THEY send back to the other person.
- Never rewrite or rephrase the received message from the sender's perspective.
- Replies must match the mode tone strictly — especially for rizz, be smooth and witty not polite.
- Keep replies short and natural. No corporate speak. No over-explaining.
- coach_note must be one punchy sentence of tactical advice.
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
    error: "You've used all " + limit + " of your free checks for today. Pro removes the limit \u2014 it's coming soon, and we're not taking payments yet. Your checks start again tomorrow.",
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
  try {
    const planRes = await fetch(SUPABASE_URL + "/rest/v1/profiles?select=plan&id=eq." + encodeURIComponent(user.id), {
      headers: { apikey: process.env.SUPABASE_SERVICE_ROLE_KEY, Authorization: "Bearer " + process.env.SUPABASE_SERVICE_ROLE_KEY },
      signal: AbortSignal.timeout(5000),
    });
    if (planRes.ok) {
      const rows = await planRes.json();
      if (Array.isArray(rows) && rows[0] && isProPlan(rows[0].plan)) return { blocked: false };
    }
    /* Plan lookup failed (no plan column yet) — treat as Free and keep
       going; never block on a lookup failure. */
  } catch (e) { /* fall through to the count check */ }
  const used = await supabaseCountToday(user.id);
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

    if (!mode || !["workplace", "relationship", "rizz", "negotiation"].includes(mode)) {
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
if (!process.env.TURNSTILE_SECRET_KEY) {
  return res.status(500).json({ error: "Server verification is not configured." });
}
    const formData = new URLSearchParams();
    formData.append("secret", process.env.TURNSTILE_SECRET_KEY);
    formData.append("response", turnstileToken);

    const turnstileResponse = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: formData,
    });

    const turnstileResult = await turnstileResponse.json();

    if (!turnstileResult.success) {
      return res.status(403).json({ error: "Verification failed. Please try again." });
    }

    if (!process.env.OPENAI_API_KEY) {
      return res.status(500).json({ error: "AI service is not configured." });
    }

    const response = await client.chat.completions.create({
      model: "gpt-5.4-nano",
      response_format: { type: "json_object" },
      temperature: 0.8,
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
