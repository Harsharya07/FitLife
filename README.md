# FitLife

**FitLife** is a full-stack fitness and wellness web application. Track workouts, explore exercises and recipes, read curated articles, and get personalized guidance from an AI coach — all in one modern, responsive interface.

Built with **React + TypeScript** on the frontend and **FastAPI + SQLite** on the backend.

---

## Table of Contents

- [About the Project](#about-the-project)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [AI Coach Setup](#ai-coach-setup)
- [Docker](#docker)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [API Overview](#api-overview)
- [Deploy on Render (Free)](#deploy-on-render-free)
- [Production Build](#production-build)
- [Image Assets](#image-assets)
- [License](#license)

---

## About the Project

FitLife helps users build healthier habits through:

- **Workout tracking** — Log sets, reps, and weight; view streaks, PRs, and a 30-day activity chart.
- **Guided sessions** — Run structured workout sessions with a built-in rest timer.
- **Content library** — 42 exercises, 12 articles, 8 blog recommendations, and 14 healthy recipes.
- **AI Coach** — Streaming chat and auto-generated diet plans, weekly meal charts, and workout routines tailored to your profile.
- **Wellness tools** — Water intake, body metrics, goals, achievements, and favorites.

The app uses JWT authentication with refresh-token rotation. User data (workouts, plans, contacts, profile) is stored in a local **SQLite** database (`fitness_site.db`).

---

## Features

### Core

| Area | What you get |
|------|----------------|
| **Auth** | Sign up, login, password reset, JWT + refresh tokens |
| **Dashboard** | Live stats, streak hero, recent activity feed |
| **Exercises** | 42 exercises across 7 categories with tips and detail modals |
| **Workouts** | Log workouts, guided session mode, rest timer |
| **Recipes & Articles** | Searchable content with category filters and detail views |
| **AI Coach** | Streaming chat, diet/workout plan generation, saved plans |
| **Wellness** | Water tracker, body metrics, goals, badges, calendar heatmap |
| **Admin** | Contact inbox and platform analytics (admin users only) |

### UI & UX

- Dark / light / system theme
- Mobile bottom navigation and PWA manifest
- Onboarding wizard for new users
- Cmd+K command palette (pages, exercises, plans)
- Skeleton loaders, empty states, and accessibility (skip link, focus rings, reduced motion)

---

## Tech Stack

| Layer | Technologies |
|-------|--------------|
| **Frontend** | React 19, TypeScript, Vite, Tailwind CSS, Framer Motion, React Router |
| **Backend** | FastAPI, Pydantic, python-jose (JWT), passlib/bcrypt |
| **AI** | Google Gemini or OpenAI-compatible APIs (streaming SSE) |
| **Database** | SQLite |
| **Testing** | pytest (backend), Vitest (frontend), Playwright (E2E smoke) |
| **DevOps** | Docker Compose, GitHub Actions CI |

---

## Prerequisites

Install these before running locally:

| Tool | Version |
|------|---------|
| **Node.js** | 18+ (22 recommended) |
| **npm** | Comes with Node |
| **Python** | 3.11+ (3.12 recommended) |
| **Git** | Any recent version |

Optional:

- **Docker & Docker Compose** — for containerized deployment
- **Google Gemini API key** — required for AI Coach features ([get one free](https://aistudio.google.com/apikey))

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Harsharya07/FitLife.git
cd FitLife
```

### 2. Configure environment

Copy the example env file to the **project root**:

```bash
cp .env.example .env
```

Edit `.env` and add your API keys (see [Environment Variables](#environment-variables) and [AI Coach Setup](#ai-coach-setup)). The backend reads `.env` from the repo root automatically.

### 3. Start the backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Leave this terminal running. Verify the API:

- Health check: http://127.0.0.1:8000/api/health
- Interactive docs: http://127.0.0.1:8000/docs

### 4. Start the frontend

Open a **new terminal** from the project root:

```bash
cd frontend
npm install
npm run dev
```

Open the app at **http://127.0.0.1:5173**

The Vite dev server proxies `/api` requests to the backend on port `8000`, so no extra CORS setup is needed during local development.

### 5. Create an account

1. Visit http://127.0.0.1:5173 and click **Sign Up**.
2. Complete the onboarding wizard (optional but recommended for AI personalization).
3. Explore the dashboard, log a workout, or open **AI Coach**.

**Admin access:** Sign up with username `admin` (or set `ADMIN_USERNAME` in `.env`) to unlock the admin contact inbox and analytics pages.

---

## Environment Variables

All variables live in `.env` at the project root. See `.env.example` for the full list.

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDER` | AI provider: `gemini` or `openai` | `gemini` |
| `GEMINI_API_KEY` | Google Gemini API key | — |
| `GEMINI_MODEL` | Gemini model name | `gemini-2.0-flash` |
| `OPENAI_API_KEY` | OpenAI (or compatible) API key | — |
| `OPENAI_MODEL` | OpenAI model name | `gpt-4o-mini` |
| `OPENAI_BASE_URL` | OpenAI-compatible base URL | `https://api.openai.com/v1` |
| `SECRET_KEY` | JWT signing secret — **change in production** | dev default |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime | `30` |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token lifetime | `7` |
| `ADMIN_USERNAME` | Username that receives admin role on signup | `admin` |
| `AI_RATE_LIMIT_REQUESTS` | Max AI requests per window | `20` |
| `AI_RATE_LIMIT_WINDOW_SECONDS` | Rate limit window (seconds) | `60` |
| `FITLIFE_ENV` | Set to `production` when deploying | `development` |

> **Never commit `.env` to git.** It is listed in `.gitignore`.

---

## AI Coach Setup

AI features (chat, diet plans, workout routines) require an API key.

1. Copy `.env.example` → `.env` if you have not already.
2. Add your Gemini key:

```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-2.0-flash
```

3. Restart the backend after changing `.env`.

The AI Coach uses your **fitness profile** (age, weight, goals, diet preferences) from Settings to personalize recommendations. Fill out your profile for the best results.

Without an API key, the rest of the app works normally — only AI endpoints will return a configuration message.

---

## Docker

Run the full stack in containers:

```bash
cp .env.example .env
# Edit .env with your API keys
docker compose up --build
```

| Service | URL |
|---------|-----|
| Frontend (nginx) | http://localhost:8080 |
| Backend API | http://localhost:8000 |
| API docs | http://localhost:8000/docs |

SQLite data is persisted in the `fitlife-data` Docker volume.

---

## Project Structure

```
FitLife/
├── .env.example              # Environment template (copy to .env)
├── .github/workflows/ci.yml  # GitHub Actions CI
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.frontend
├── fitness_site.db           # SQLite database (created/updated at runtime)
├── scripts/
│   └── download_images.py    # Fetch curated stock images
├── backend/
│   ├── app/
│   │   ├── routers/          # auth, ai, plans, activity, content, admin, …
│   │   ├── services/         # LLM, RAG, achievements
│   │   ├── data/             # Static exercises, articles, recipes, blogs
│   │   ├── config.py
│   │   ├── database.py
│   │   └── main.py
│   ├── requirements.txt
│   └── tests/
└── frontend/
    ├── public/images/        # Exercise, recipe, article, blog images
    ├── src/
    │   ├── components/       # UI components (chat, modals, charts, …)
    │   ├── pages/            # Route pages
    │   ├── context/          # Auth & theme providers
    │   └── lib/              # API client, utilities
    ├── package.json
    └── vite.config.ts        # Dev proxy: /api → localhost:8000
```

---

## Testing

```bash
# Backend unit tests
cd backend
source venv/bin/activate
pytest -v

# Frontend unit tests
cd frontend
npm test

# Frontend E2E smoke test (requires backend running)
cd frontend
npm run test:e2e
```

CI runs backend pytest, frontend build, and frontend Vitest on every push to `main`.

---

## API Overview

When the backend is running, full interactive documentation is at `/docs`.

Common endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/signup` | Create account |
| `POST` | `/api/auth/login` | Login (access + refresh tokens) |
| `POST` | `/api/auth/refresh` | Rotate tokens |
| `GET` | `/api/activity/dashboard` | User dashboard stats |
| `POST` | `/api/activity/workouts` | Log a workout |
| `GET/POST/DELETE` | `/api/plans` | Saved AI plans |
| `POST` | `/api/ai/chat/stream` | Streaming AI chat (SSE) |
| `POST` | `/api/ai/generate/*` | Generate and save diet/workout plans |
| `GET` | `/api/content/exercises` | Exercise library |
| `GET` | `/api/admin/contacts` | Admin contact inbox |

---

## Deploy on Render (Free)

This repo includes a [`render.yaml`](./render.yaml) Blueprint that deploys both the backend and frontend in one step.

### One-click deploy

1. Go to [Render Dashboard → New Blueprint](https://dashboard.render.com/select-repo?type=blueprint)
2. Connect GitHub and select the **FitLife** repository
3. Render detects `render.yaml` and shows two services:
   - **fitlife-api** — FastAPI backend (Docker, free tier)
   - **fitlife** — React static site with `/api` proxy
4. When prompted, enter:
   - **SECRET_KEY** — generate with `openssl rand -hex 32`
   - **GEMINI_API_KEY** — from [Google AI Studio](https://aistudio.google.com/apikey)
5. Click **Apply** and wait ~10 minutes for both services to build

Your app will be live at:

| Service | URL |
|---------|-----|
| Frontend | `https://fitlife.onrender.com` |
| Backend API | `https://fitlife-api.onrender.com` |

Verify the backend: `https://fitlife-api.onrender.com/api/health`

### Notes

- **Free tier** services sleep after ~15 min idle; first request may take 30–60s (cold start).
- **SQLite data** on free tier is ephemeral — user data resets on redeploy. Fine for demos.
- If you rename the backend service, update the `/api/*` rewrite destination in `render.yaml` to match.
- Manual step-by-step deploy instructions are also available in the conversation history or by deploying each service separately from the Render dashboard.

---

## Production Build

```bash
# Build the frontend static bundle
cd frontend
npm run build
# Output: frontend/dist/
```

Before deploying:

1. Set `FITLIFE_ENV=production` in your environment.
2. Set a strong, unique `SECRET_KEY` (the app refuses to start in production with the dev default).
3. Configure your reverse proxy to serve `frontend/dist` and proxy `/api` to the FastAPI backend.
4. Keep `.env` out of version control and inject secrets via your hosting platform.

---

## Image Assets

Content images (exercises, recipes, articles, blogs) are stored in `frontend/public/images/`. They were downloaded from free stock sources (Pexels / Unsplash) using:

```bash
python3 scripts/download_images.py
```

Attribution details are in [ATTRIBUTIONS.md](./ATTRIBUTIONS.md).

---

## License

MIT
