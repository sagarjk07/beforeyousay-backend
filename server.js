const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const OpenAI = require("openai");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("BeforeYouSay backend is live");
});

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

function getPrompt(mode, message) {
  if (mode === "workplace") {
    return `Make this professional and clear:\n${message}`;
  }

  if (mode === "relationship") {
    return `Make this emotionally intelligent and calm:\n${message}`;
  }

  if (mode === "rizz") {
    return `Make this flirty, confident, and natural:\n${message}`;
  }

  if (mode === "negotiation") {
    return `Make this persuasive and confident:\n${message}`;
  }

  return message;
}

app.post("/analyze", async (req, res) => {
  try {
    const { message, mode } = req.body;

    const response = await client.chat.completions.create({
      model: "gpt-5.4-nano",
      messages: [
        { role: "system", content: "You are BeforeYouSay AI." },
        { role: "user", content: getPrompt(mode, message) }
      ],
    });

    console.log("FULL OPENAI RESPONSE:", JSON.stringify(response, null, 2));

    const result =
      response?.choices?.[0]?.message?.content ||
      "AI responded, but no text content was returned.";

    res.json({ result });
  } catch (error) {
    console.error("OpenAI error:", error.message);
    res.status(500).json({
      error: error.message || "Something went wrong",
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
