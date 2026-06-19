"""Local image paths served from frontend/public/images (Unsplash + Pexels, free licenses)."""


def img(path: str) -> str:
    return f"/images/{path}"
