from opencyber.policy import canonical_http_url, credential_boundary_changed, target_matches


def test_target_matches_scope_guard():
    assert target_matches("api.example.com", "example.com") is True
    assert target_matches("evil.com", "example.com") is False
    assert target_matches("127.0.0.1", "127.0.0.1") is True


def test_credential_boundary_changed():
    assert credential_boundary_changed("https://a.example.com/1", "https://a.example.com/2") is False
    assert credential_boundary_changed("https://a.example.com/1", "https://b.example.com/1") is True
