from unittest.mock import AsyncMock, patch


def test_ai_status(client, auth_headers):
    resp = client.get("/api/ai/status", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["configured"] is False


@patch("app.routers.ai.generate_ai_response", new_callable=AsyncMock)
def test_chat_saves_messages(mock_generate, client, auth_headers):
    mock_generate.return_value = "Drink more water!"

    resp = client.post(
        "/api/ai/chat",
        json={"message": "How much water should I drink?"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert "water" in resp.json()["reply"].lower()

    history = client.get("/api/ai/chat/history", headers=auth_headers)
    assert len(history.json()) == 2


@patch("app.routers.ai.generate_ai_response", new_callable=AsyncMock)
def test_generate_diet_plan_saves(mock_generate, client, auth_headers):
    mock_generate.return_value = "# Your 7-day plan\n\nDay 1: eggs"

    resp = client.post(
        "/api/ai/generate/diet-plan",
        json={"days": 7},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "diet-plan"
    assert data["plan_id"] is not None

    plans = client.get("/api/plans", headers=auth_headers)
    assert len(plans.json()) == 1
