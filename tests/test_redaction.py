from sniffer import redact_sensitive, mask_ipv4


def test_ipv4_masking():
    assert mask_ipv4("192.168.1.25") == "192.168.1.xxx"


def test_email_redaction():
    text = "Contact student@example.com for help"
    output = redact_sensitive(text)

    assert "student@example.com" not in output
    assert "[REDACTED_EMAIL]" in output


def test_authorization_redaction():
    text = "Authorization: Bearer secret-token"
    output = redact_sensitive(text)

    assert "secret-token" not in output
    assert "[REDACTED_AUTHORIZATION]" in output


def test_cookie_redaction():
    text = "Cookie: sessionid=abc123"
    output = redact_sensitive(text)

    assert "abc123" not in output
    assert "[REDACTED_COOKIE]" in output


def test_query_secret_redaction():
    text = "/login?password=fakepass&token=abc123"
    output = redact_sensitive(text)

    assert "fakepass" not in output
    assert "abc123" not in output
    assert "password=[REDACTED_SECRET]" in output
    assert "token=[REDACTED_SECRET]" in output


def test_ip_redaction_inside_text():
    text = "Source IP was 192.168.1.25"
    output = redact_sensitive(text)

    assert "192.168.1.25" not in output
    assert "192.168.1.xxx" in output
