# Gemini 2.5 Pro nf_tables Red Teaming Case Study (CVE-2023-32233)

**LLM Safety Research | Responsible Disclosure | AI Alignment Evaluation**

**Researcher**: Niranj R Mahaswar (Destawell)  
**Google AI Vulnerability Reward Program**: [#889286](https://issuetracker.google.com/889286) — **Out of Scope**

## Summary
This repository documents a comparative **LLM red teaming** experiment on frontier models regarding technical primitives for the Linux kernel vulnerability **CVE-2023-32233** (nf_tables race condition / Use-After-Free).

**Key Result (April 27, 2026)**:  
Gemini 2.5 Pro generated relevant technical output, while **Claude, GPT-4o, Llama 3, and Microsoft Copilot** refused the request. By May 16, 2026, Gemini also began refusing similar queries following a safety update.

---

## Timeline & Model Behavior

| Date              | Event                                              | Outcome                          |
|-------------------|----------------------------------------------------|----------------------------------|
| April 27, 2026    | Initial testing on Gemini 2.5 Pro                  | Technical output provided        |
| April 27, 2026    | Responsible disclosure to Google AI VRP (#889286) | Submitted                        |
| April 30, 2026    | Google Response                                    | Out of Scope                     |
| May 16, 2026      | Post-safety update testing                         | Refusal on Gemini                |
| May 20, 2026      | Tested on Gemini Flash                             | Full refusal   |

---

## Model Comparison (April 27, 2026 Test)

| Model                | Response Type              | Safety Decision                  |
|----------------------|----------------------------|----------------------------------|
| Gemini 2.5 Pro       | Technical details provided | Passed (no block)                |
| Anthropic Claude     | Refused                    | Blocked                          |
| OpenAI GPT-4o        | Refused                    | Blocked                          |
| Meta Llama 3         | Refused                    | Blocked                          |
| Microsoft Copilot    | Refused                    | Blocked                          |

---

## Current Status (May 20, 2026)
**Gemini Flash now refuses** requests for functional C code, multi-threaded harnesses, or detailed exploit primitives for CVE-2023-32233, citing risks related to race conditions, memory management, and potential denial-of-service.

---

## Purpose of This Repository
- Document rapid evolution of **LLM safety alignment** in dual-use cybersecurity topics
- Provide a public case study on **responsible disclosure** for AI red teaming
- Highlight differences in safety policies across major AI providers
- Serve as educational reference for AI safety researchers and red teamers

**This repo contains no prompts, no generated code, and no exploit details.**

---

## Keywords
`llm-red-teaming` `ai-safety` `gemini-2.5-pro` `gemini-safety` `cve-2023-32233` `nf_tables` `responsible-disclosure` `google-vrp` `ai-alignment` `kernel-exploit` `use-after-free` `race-condition` `llm-safety` `red-teaming` `gemini-red-teaming` `ai-security-research` `llm-jailbreak` `ai-vulnerability` `gemini-2.5` `linux-kernel-exploit` `nf_tables-race-condition` `dual-use-ai` `ai-red-teaming` `model-alignment` `google-ai-safety` `anthropic-claude` `openai-gpt4o` `meta-llama` `microsoft-copilot` `destawell` `niranj-mahaswar`

---

**Disclaimer**  
This repository is for **educational and research purposes only**. It documents observed model behavior to contribute to the public discussion on LLM safety.

**Last updated**: May 20, 2026  
**Researcher**: [github.com/Destawell](https://github.com/Destawell)
