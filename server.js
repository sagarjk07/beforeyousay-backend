const express = require("express");
const express = require('express');
const cors = require('cors');

const app = express();  // <- app must exist FIRST

// CORS goes AFTER app is created
app.use(cors({
  origin: ['https://beforeyousay.com', 'https://www.beforeyousay.com'],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json());

// Your routes here
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'BeforeYouSay backend', time: new Date().toISOString() });
});

app.post('/analyze', (req, res) => {
  // your analysis code
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
const dotenv = require("dotenv");
const OpenAI = require("openai");

dotenv.config();

const app = express();

app.use(cors());
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

app.post("/analyze", async (req, res) => {
  try {
    const { message, mode } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Message is required." });
    }

    if (!mode || !["workplace", "relationship", "rizz", "negotiation"].includes(mode)) {
      return res.status(400).json({ error: "Valid mode is required." });
    }

    const response = await client.chat.completions.create({
      model: "gpt-5.4-nano",
      response_format: { type: "json_object" },
      temperature: 0.8,
      messages: [
        {
          role: "system",
          content: buildSystemPrompt(mode),
        },
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
