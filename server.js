const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const OpenAI = require("openai");
const rateLimit = require("express-rate-limit");
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

function buildSystemPrompt(mode) {
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

  return `${commonRules}\n${modeGuidance[mode] || ""}\n${outputFormat}`;
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
function buildReplyPrompt(mode) {
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
`;
}
app.use("/analyze", limiter);

app.post("/analyze", analyzeLimiter, async (req, res) => {
  try {
    const { message, mode, turnstileToken, replyMode } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Message is required." });
    }
    if (message.trim().length > 1000) {
      return res.status(400).json({ error: "Message is too long. Please keep it under 1000 characters." });
    }

    if (!mode || !["workplace", "relationship", "rizz", "negotiation"].includes(mode)) {
      return res.status(400).json({ error: "Valid mode is required." });
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
       { role: "system", content: replyMode ? buildReplyPrompt(mode) : buildSystemPrompt(mode) },
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
