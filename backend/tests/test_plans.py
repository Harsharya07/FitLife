def test_create_list_delete_plan(client, auth_headers):
    create = client.post(
        "/api/plans",
        json={
            "title": "My Diet Plan",
            "plan_type": "diet-plan",
            "content": "# Day 1\n- Oatmeal",
        },
        headers=auth_headers,
    )
    assert create.status_code == 200
    plan_id = create.json()["id"]

    listing = client.get("/api/plans", headers=auth_headers)
    assert len(listing.json()) == 1

    get_one = client.get(f"/api/plans/{plan_id}", headers=auth_headers)
    assert get_one.json()["title"] == "My Diet Plan"

    deleted = client.delete(f"/api/plans/{plan_id}", headers=auth_headers)
    assert deleted.status_code == 200

    listing = client.get("/api/plans", headers=auth_headers)
    assert len(listing.json()) == 0


def test_filter_plans_by_type(client, auth_headers):
    client.post(
        "/api/plans",
        json={"title": "Diet", "plan_type": "diet-plan", "content": "content"},
        headers=auth_headers,
    )
    client.post(
        "/api/plans",
        json={"title": "Workout", "plan_type": "workout-plan", "content": "content"},
        headers=auth_headers,
    )
    resp = client.get("/api/plans?plan_type=workout-plan", headers=auth_headers)
    assert len(resp.json()) == 1
    assert resp.json()[0]["plan_type"] == "workout-plan"
