# OWASP Agentic AI GOAT Workshop Outline

**OWASP Agentic AI GOAT — Hands-On Security Workshop**
*Draft for RSA Conference*

---

## 1. Workshop Overview

| Item | Details |
|------|---------|
| **Title** | OWASP Agentic AI GOAT: Web & AI Security in a Safe Lab |
| **Format** | Hands-on lab with guided challenges |
| **Duration** | ~90–120 minutes (adjustable) |
| **Audience** | Security practitioners, penetration testers, developers (RSA attendees) |
| **Platform** | OWASP Agentic AI GOAT v2.0 — secure platform with isolated vulnerable challenges |

**What we’ll do:** Use a single application to practice web vulnerabilities (SQLi, XSS) and AI security (prompt injection, CTF) in isolated environments. The platform stays secure; the lab is the target.

---

## 2. Learning Objectives

By the end of the workshop, participants will have:

- Used **SQL injection** and **XSS** in isolated challenge environments.
- Explored **direct and indirect prompt injection** against an AI assistant.
- Attempted **CTF-style prompt injection** levels (e.g., 8 levels with Llama 3.1).
- Used **SecureShop** to find bugs and test an AI chatbot.
- Understood **database isolation**: why the platform stays safe while challenges are exploitable.

---

## 3. Prerequisites & Setup

- **Provided:** Lab URL (e.g. `http://localhost:3000` or instructor-provided URL).
- **Optional:** Laptop with browser; no mandatory install if using hosted lab.
- **If self-hosted:** Follow the current [installation requirements](../install/INSTALLATION.md), then run `./start_all.sh`.

---

## 4. Ground Rules (One Slide)

- **In scope:** Only the OWASP Agentic AI GOAT app and lab; only provided accounts and URLs.
- **Out of scope:** No conference Wi‑Fi, other attendees, venue systems, or real data.
- **No:** DoS, abuse of shared lab, or anything illegal.
- **Conduct:** Don’t break others’ sessions; ask before heavy or custom testing.
- **Found a real bug?** Tell the facilitator privately; don’t exploit or announce it.
- **Rule:** Attack the app only — not the room, network, or people.

---

## 5. Agenda / Workshop Outline

| # | Section | Time | Description |
|---|---------|------|-------------|
| 1 | **Intro & setup** | ~10 min | What is OWASP Agentic AI GOAT; lab access; quick tour of main app and workshop login. |
| 2 | **Platform & login** | ~5 min | Log in as student (`student` / `student 123`) or admin (`admin` / `admin123`); dashboards and navigation. |
| 3 | **Web security** | ~25 min | **SQL injection** (isolated DB), **XSS** (comment system), **SQL/NoSQL workshop** (prompt-driven queries). Emphasize: only challenge DBs are vulnerable. |
| 4 | **AI security** | ~25 min | **Direct prompt injection** → **Indirect prompt injection** → **CTF prompt injection** (8 levels). Hands-on with Llama 3.1 in the app. |
| 5 | **SecureShop** | ~15 min | Open the separate e-commerce app, use its own shop sign-in, find bugs, test checkout/payment flow, and attack the AI customer service bot. |
| 6 | **Admin & teaching** | ~10 min | Admin dashboard: challenge visibility, student progress, solutions. How to run this workshop with students. |
| 7 | **Wrap-up** | ~5 min | Recap (platform vs. lab); learning path (SQLi → XSS → prompt injection); repo and docs. |

**Total:** ~95 min (expand or trim sections as needed).

---

## 6. Access & Login Reference

**Platform (workshop login):**

| Role    | Username | Password   | Use |
|---------|----------|------------|-----|
| Student | `student` | `student 123` | Challenge access, workshop dashboard |
| Admin   | `admin` | `admin123` | Full access, admin dashboard |

**SecureShop practice (separate application):**

| Purpose        | Username   | Password     |
|----------------|------------|--------------|
| Shop customer | `student_customer` | `student123` |
| Shop merchant | `student_merchant` | `student123` |
| Shop administrator | `student_admin` | `student123` |

**URLs (adjust if using hosted lab):**

- Main app: `http://localhost:3000` (or instructor URL)
- Workshop login: `.../workshop-login`
- SecureShop guest storefront: `.../secureshop`
- SecureShop sign-in: `.../secureshop/login`
- Student dashboard: `.../workshop-dashboard`
- Admin dashboard: `.../admin`
- CTF: `.../ctf`

---

## 7. Section Notes (Facilitator)

- **Web security:** Point participants to SQL Injection and XSS challenges; briefly show SQL/NoSQL workshop and how prompts can build queries.
- **AI security:** Start with one direct prompt injection example, then indirect (e.g. “document” with hidden instructions), then CTF levels. Clarify that the AI (Llama 3.1) is in the lab only.
- **SecureShop:** Open the separate app directly. Guests can browse its catalog;
  customer, merchant and shop-administrator work uses the independent shop sign-in.
- **Admin:** Optional; useful for trainers who may run the workshop later.

---

## 8. Wrap-Up & Resources

- **Repo:** [GitHub – OWASP Agentic AI GOAT]
- **Docs:** README.md, INSTALL_GUIDE.md (and this outline).
- **Learning path:** SQLi → XSS → Direct/Indirect prompt injection → CTF → SecureShop.

---

*Document: Workshop Outline (draft)*  
*Last updated: [Date]*
