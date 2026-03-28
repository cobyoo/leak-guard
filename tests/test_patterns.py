"""Tests for secret detection patterns."""

from leak_guard.scanner import scan_content


def test_aws_access_key():
    content = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
    findings = scan_content(content)
    assert any("AWS" in f.pattern_name for f in findings)


def test_github_token():
    content = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
    findings = scan_content(content)
    assert any("GitHub" in f.pattern_name for f in findings)


def test_private_key():
    content = "-----BEGIN RSA PRIVATE KEY-----"
    findings = scan_content(content)
    assert any("Private Key" in f.pattern_name for f in findings)


def test_jwt_token():
    content = 'auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
    findings = scan_content(content)
    assert any("JWT" in f.pattern_name for f in findings)


def test_google_api_key():
    content = 'GOOGLE_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"'
    findings = scan_content(content)
    assert any("Google" in f.pattern_name for f in findings)


def test_stripe_key():
    content = 'stripe_key = "sk_live_' + 'x' * 24 + '"'
    findings = scan_content(content)
    assert any("Stripe" in f.pattern_name for f in findings)


# --- Korean service tests ---


def test_kakao_rest_api_key():
    content = 'KAKAO_REST_API_KEY = "abcdef1234567890abcdef1234567890"'
    findings = scan_content(content)
    assert any("Kakao" in f.pattern_name for f in findings)


def test_kakao_admin_key():
    content = 'kakao_admin_key = "abcdef1234567890abcdef1234567890"'
    findings = scan_content(content)
    assert any("Kakao Admin" in f.pattern_name for f in findings)


def test_naver_client_secret():
    content = 'NAVER_CLIENT_SECRET = "abcdefghijklmn"'
    findings = scan_content(content)
    assert any("Naver" in f.pattern_name for f in findings)


def test_toss_payments_key():
    content = 'TOSS_SECRET_KEY = "live_sk_abcdefghij1234567890ab"'
    findings = scan_content(content)
    assert any("Toss" in f.pattern_name for f in findings)


def test_iamport_key():
    content = 'IAMPORT_API_KEY = "abcdefghij1234567890ab"'
    findings = scan_content(content)
    assert any("Iamport" in f.pattern_name or "PortOne" in f.pattern_name for f in findings)


def test_no_false_positive_on_comments():
    content = '# KAKAO_REST_API_KEY = "abcdef1234567890abcdef1234567890"'
    findings = scan_content(content)
    assert len(findings) == 0


def test_no_false_positive_on_clean_code():
    content = """
import os
x = 1 + 2
print("hello world")
def foo():
    return True
"""
    findings = scan_content(content)
    assert len(findings) == 0


def test_severity_filter():
    content = 'KAKAO_JS_KEY = "abcdef1234567890abcdef1234567890"'
    findings = scan_content(content)
    js_findings = [f for f in findings if "JavaScript" in f.pattern_name]
    if js_findings:
        assert js_findings[0].severity == "medium"
