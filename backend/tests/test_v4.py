"""Tests for v4 features: wellness, sessions, favorites, share, password reset."""


def test_wellness_water_and_metrics(client, auth_headers):
    r = client.post("/api/wellness/water", json={"glasses": 2}, headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["glasses"] == 2

    r = client.get("/api/wellness/water/today", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["glasses"] >= 2

    r = client.post(
        "/api/wellness/metrics",
        json={"weight_kg": 75.5, "body_fat_pct": 18.0},
        headers=auth_headers,
    )
    assert r.status_code == 200
    assert r.json()["weight_kg"] == 75.5

    r = client.get("/api/wellness/metrics", headers=auth_headers)
    assert r.status_code == 200
    assert len(r.json()) >= 1


def test_wellness_goals_and_badges(client, auth_headers):
    r = client.post(
        "/api/wellness/goals",
        json={"title": "Run 10 workouts", "goal_type": "workouts", "target_value": 10, "unit": "workouts"},
        headers=auth_headers,
    )
    assert r.status_code == 200
    goal_id = r.json()["id"]

    r = client.patch(
        f"/api/wellness/goals/{goal_id}",
        json={"current_value": 5},
        headers=auth_headers,
    )
    assert r.status_code == 200
    assert r.json()["current_value"] == 5

    r = client.get("/api/wellness/badges", headers=auth_headers)
    assert r.status_code == 200
    badges = r.json()
    assert any(b["badge_id"] == "first_goal" and b["earned"] for b in badges)

    r = client.get("/api/wellness/calendar?days=7", headers=auth_headers)
    assert r.status_code == 200
    assert len(r.json()) == 7


def test_workout_session_flow(client, auth_headers):
    r = client.post("/api/sessions/start", json={"name": "Test Session"}, headers=auth_headers)
    assert r.status_code == 200
    session_id = r.json()["id"]
    assert r.json()["status"] == "active"

    r = client.get("/api/sessions/active", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["id"] == session_id

    r = client.post(
        f"/api/sessions/{session_id}/log",
        json={
            "exercise_id": "push-ups",
            "exercise_name": "Push Ups",
            "sets": 3,
            "reps": 12,
        },
        headers=auth_headers,
    )
    assert r.status_code == 200

    r = client.post(f"/api/sessions/{session_id}/finish", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["status"] == "completed"
    assert r.json()["exercise_count"] >= 1


def test_favorites_and_export(client, auth_headers):
    r = client.post(
        "/api/favorites",
        json={"item_type": "exercise", "item_id": "push-ups"},
        headers=auth_headers,
    )
    assert r.status_code == 200

    r = client.get("/api/favorites/check/exercise/push-ups", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["favorited"] is True

    r = client.get("/api/favorites", headers=auth_headers)
    assert r.status_code == 200
    assert len(r.json()) >= 1

    r = client.delete("/api/favorites/exercise/push-ups", headers=auth_headers)
    assert r.status_code == 200

    r = client.get("/api/export", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "workouts" in data
    assert "goals" in data


def test_plan_share_public(client, auth_headers):
    r = client.post(
        "/api/plans",
        json={"title": "Share Test", "plan_type": "workout-plan", "content": "Day 1: Squats"},
        headers=auth_headers,
    )
    assert r.status_code == 200
    plan_id = r.json()["id"]

    r = client.post(f"/api/plans/{plan_id}/share", headers=auth_headers)
    assert r.status_code == 200
    token = r.json()["share_token"]

    r = client.get(f"/api/public/plans/{token}")
    assert r.status_code == 200
    assert r.json()["title"] == "Share Test"
    assert "Squats" in r.json()["content"]


def test_password_reset_flow(client):
    client.post(
        "/api/auth/signup",
        json={"username": "resetuser", "password": "oldpass123", "confirm_password": "oldpass123"},
    )

    r = client.post("/api/auth/forgot-password", json={"username": "resetuser"})
    assert r.status_code == 200
    token = r.json()["reset_token"]
    assert token

    r = client.post(
        "/api/auth/reset-password",
        json={"token": token, "new_password": "newpass456", "confirm_password": "newpass456"},
    )
    assert r.status_code == 200

    r = client.post("/api/auth/login", json={"username": "resetuser", "password": "newpass456"})
    assert r.status_code == 200
    assert "access_token" in r.json()
