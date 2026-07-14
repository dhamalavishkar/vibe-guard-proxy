require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { GoogleGenAI, Type } = require('@google/genai');
const { OpenAI } = require('openai');

const app = express();
app.use(cors());
// Allow massive payloads because workspace scanning sends many files at once
app.use(express.json({ limit: '50mb' }));

// Use the API keys from the environment variables securely
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
const openai = new OpenAI({ 
    baseURL: "https://openrouter.ai/api/v1",
    apiKey: process.env.OPENROUTER_API_KEY || 'dummy_key_to_prevent_crash_if_missing' 
});

// The Free-Tier Limit: 10 scans per 15 minutes per IP address
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10,
    message: { error: 'Too many scans from this IP, please try again after 15 minutes.' }
});
app.use('/api/', limiter);

// Strict Output Schema
const responseSchema = {
    type: Type.OBJECT,
    properties: {
        summary: { type: Type.STRING },
        isSecure: { type: Type.BOOLEAN },
        items: {
            type: Type.ARRAY,
            items: {
                type: Type.OBJECT,
                properties: {
                    id: { type: Type.STRING },
                    type: { type: Type.STRING },
                    severity: { type: Type.STRING },
                    problem: { type: Type.STRING },
                    fixSnippet: { type: Type.STRING },
                    startLine: { type: Type.INTEGER },
                    endLine: { type: Type.INTEGER },
                    filepath: { type: Type.STRING }
                },
                required: ["id", "type", "severity", "problem", "fixSnippet", "startLine", "endLine", "filepath"]
            }
        }
    },
    required: ["summary", "isSecure", "items"]
};

// Simplified schema just for fixing a syntax error
const fixSchema = {
    type: Type.OBJECT,
    properties: {
        correctedFixSnippet: { type: Type.STRING }
    },
    required: ["correctedFixSnippet"]
};

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function callOpenAIModel(prompt, customSchema) {
    console.log(`[Backend] 🚀 Attempting Ultimate Fallback: OpenRouter (Llama 3.1 8B Free)`);
    try {
        const chatCompletion = await openai.chat.completions.create({
            messages: [
                {
                    role: 'system',
                    content: `You are a Principal Security Engineer. You MUST strictly output your response in valid JSON matching exactly this schema structure:\n${JSON.stringify(customSchema)}`
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            model: 'meta-llama/llama-3.1-8b-instruct:free',
            temperature: 0.1,
            // Note: OpenRouter handles json_object for many models automatically
            response_format: { type: 'json_object' }
        });
        return JSON.parse(chatCompletion.choices[0]?.message?.content || "{}");
    } catch (e) {
        console.error(`[Backend] ❌ OpenRouter Fallback failed:`, e.message);
        throw new Error(`Both Google and OpenRouter models failed. OpenRouter Error: ${e.message}`);
    }
}

async function callModel(prompt, customSchema = responseSchema) {
    const modelsToTry = ['gemini-2.0-flash', 'gemini-flash-latest', 'gemini-3.5-flash'];
    let lastError;

    for (const modelName of modelsToTry) {
        try {
            console.log(`[Backend] Attempting model: ${modelName} (10s timeout, no retries)`);
            
            // Create a 10-second timeout promise
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('10s Timeout Exceeded')), 10000)
            );
            
            // Create the API call promise
            const apiPromise = ai.models.generateContent({
                model: modelName,
                contents: prompt,
                config: {
                    responseMimeType: 'application/json',
                    responseSchema: customSchema,
                    temperature: 0.1
                }
            });

            // Race them! If the API takes longer than 10s, it instantly throws.
            const response = await Promise.race([apiPromise, timeoutPromise]);
            return JSON.parse(response.text);
            
        } catch (error) {
            lastError = error;
            console.error(`[Backend] ❌ Model ${modelName} failed or timed out:`, error.message);
            // Move immediately to the next Gemini model with NO retries
        }
    }
    
    // If we exhaust the entire Google array, initiate OpenRouter Fallback
    console.warn(`[Backend] 🚨 Google API completely exhausted. Initiating OpenRouter Free Fallback...`);
    if (!process.env.OPENROUTER_API_KEY || process.env.OPENROUTER_API_KEY.includes('dummy')) {
        throw new Error("All Google models failed, and OPENROUTER_API_KEY is not configured in .env for fallback.");
    }
    
    return await callOpenAIModel(prompt, customSchema);
}

app.post('/api/scan', async (req, res) => {
    try {
        const { codeSnippet, filepath } = req.body;
        console.log(`[Backend] Received scan request for: ${filepath}`);
        const prompt = `You are a Principal Security Engineer. Analyze this file:\n\n=== FILE: ${filepath} ===\n${codeSnippet}\n\nCRITICAL RULES:\n1. DO NOT alter, optimize, or remove the core business logic, custom algorithms (like Bubble Sort), or intended behavior of the program. Your ONLY job is to fix objective security vulnerabilities, memory leaks, and syntax errors.\n2. If the code is perfectly secure, set isSecure to true, write a congratulatory summary, and return an empty array for items.`;
        const plan = await callModel(prompt);
        res.json(plan);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/scan-workspace', async (req, res) => {
    try {
        const { workspaceContext } = req.body;
        console.log(`[Backend] Received massive workspace scan request!`);
        const prompt = `You are a Principal Security Engineer. Analyze this entire workspace project context and identify vulnerabilities and objective bugs across ALL files.\n\n${workspaceContext}\n\nCRITICAL RULES:\n1. You MUST deeply review EVERY SINGLE FILE provided in the context. Do not skip any files (e.g. vulnerable.js).\n2. DO NOT alter, optimize, or remove the core business logic, custom algorithms (like Bubble Sort), or intended behavior of the program. Your ONLY job is to fix true security vulnerabilities, SQL injections, XSS, and syntax errors.\n3. Always include the exact absolute filepath for every issue.\n4. If all files are perfectly secure, set isSecure to true, write a congratulatory summary, and return an empty array for items.`;
        const plan = await callModel(prompt);
        res.json(plan);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/fix-syntax', async (req, res) => {
    try {
        const { originalCode, failedFix, compilerError } = req.body;
        console.log(`[Backend] Received syntax auto-fix request!`);
        const prompt = `You previously proposed a code fix, but your fix introduced a compiler/syntax error!
        
Original Code:
${originalCode}

Your Failed Fix snippet:
${failedFix}

The Compiler Error your fix caused:
${compilerError}

Please provide a correctedFixSnippet that cleanly replaces the original code WITHOUT causing this syntax error. Maintain exact indentation!`;
        const plan = await callModel(prompt, fixSchema);
        res.json(plan);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: e.message });
    }
});

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`🛡️ Vibe-Guard Backend Proxy running on http://localhost:${PORT}`);
    });
}

// Required for Vercel Serverless Deployment
module.exports = app;
