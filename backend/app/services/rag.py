"""Simple keyword RAG over exercises, articles, and recipes."""

from app.data.articles import ARTICLES
from app.data.exercises import EXERCISE_CATEGORIES
from app.data.recipes import RECIPES


def _tokenize(text: str) -> set[str]:
    return {w.lower() for w in text.split() if len(w) > 2}


def _score(query_tokens: set[str], doc_tokens: set[str]) -> float:
    if not query_tokens or not doc_tokens:
        return 0.0
    overlap = len(query_tokens & doc_tokens)
    return overlap / len(query_tokens)


def search_content(query: str, limit: int = 5) -> list[dict]:
    q_tokens = _tokenize(query)
    results: list[tuple[float, dict]] = []

    for cat in EXERCISE_CATEGORIES:
        for ex in cat["exercises"]:
            text = f"{ex['name']} {ex['description']} {' '.join(ex['tags'])} {ex['tip']}"
            score = _score(q_tokens, _tokenize(text))
            if score > 0:
                results.append((score, {
                    "type": "exercise",
                    "id": ex["id"],
                    "title": ex["name"],
                    "snippet": ex["description"][:200],
                    "category": cat["name"],
                }))

    for art in ARTICLES:
        text = f"{art['title']} {art['excerpt']} {' '.join(art['categories'])}"
        score = _score(q_tokens, _tokenize(text))
        if score > 0:
            results.append((score, {
                "type": "article",
                "id": art["id"],
                "title": art["title"],
                "snippet": art["excerpt"][:200],
            }))

    for rec in RECIPES:
        text = f"{rec['name']} {rec['description']} {' '.join(rec['ingredients'])}"
        score = _score(q_tokens, _tokenize(text))
        if score > 0:
            results.append((score, {
                "type": "recipe",
                "id": rec["id"],
                "title": rec["name"],
                "snippet": rec["description"][:200],
            }))

    results.sort(key=lambda x: x[0], reverse=True)
    return [r[1] for r in results[:limit]]


def build_rag_context(query: str) -> str:
    hits = search_content(query, limit=4)
    if not hits:
        return ""
    lines = ["Relevant FitLife library content (cite when helpful):"]
    for h in hits:
        lines.append(f"- [{h['type']}] {h['title']}: {h['snippet']}")
    return "\n".join(lines)


def recipe_list_for_prompt() -> str:
    names = [f"- {r['name']} ({r['calories']}, {r['prep_time']})" for r in RECIPES[:14]]
    return "Available FitLife recipes:\n" + "\n".join(names)
