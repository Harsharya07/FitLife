def test_log_workout_and_dashboard(client, auth_headers):
    resp = client.post(
        "/api/activity/workouts",
        json={
            "exercise_id": "push-ups",
            "exercise_name": "Push Ups",
            "sets": 3,
            "reps": 15,
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["exercise_name"] == "Push Ups"

    stats = client.get("/api/activity/dashboard", headers=auth_headers)
    assert stats.status_code == 200
    data = stats.json()
    assert data["total_workouts"] == 1
    assert data["workouts_this_week"] == 1
    assert data["current_streak"] >= 1


def test_weekly_activity(client, auth_headers):
    client.post(
        "/api/activity/workouts",
        json={"exercise_id": "squats", "exercise_name": "Squats", "sets": 4, "reps": 12},
        headers=auth_headers,
    )
    resp = client.get("/api/activity/weekly", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 7


def test_exercise_count(client, auth_headers):
    client.post(
        "/api/activity/workouts",
        json={"exercise_id": "plank", "exercise_name": "Plank", "duration_min": 2},
        headers=auth_headers,
    )
    resp = client.get("/api/activity/workouts/exercise/plank/count", headers=auth_headers)
    assert resp.json()["count"] == 1
