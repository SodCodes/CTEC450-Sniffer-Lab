from sniffer import parse_http_from_payload, sanitize_value


def test_http_request_parsing():
    payload = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: localhost:8000\r\n"
        b"\r\n"
    )

    result = parse_http_from_payload(payload)

    assert result is not None
    assert result["method"] == "GET"
    assert result["path"] == "/index.html"
    assert result["host"] == "localhost:8000"


def test_http_sensitive_path_gets_redacted_after_sanitizing():
    payload = (
        b"GET /login?email=student@example.com&token=abc123 HTTP/1.1\r\n"
        b"Host: localhost:8000\r\n"
        b"\r\n"
    )

    result = parse_http_from_payload(payload)
    sanitized = sanitize_value(result)

    assert "student@example.com" not in str(sanitized)
    assert "abc123" not in str(sanitized)
    assert "[REDACTED_EMAIL]" in str(sanitized)
    assert "token=[REDACTED_SECRET]" in str(sanitized)
