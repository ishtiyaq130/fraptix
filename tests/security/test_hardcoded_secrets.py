import ast
from pathlib import Path

from fraptix.rules.security.hardcoded_secrets import HardcodedSecretsRule


RULE = HardcodedSecretsRule()
FILE = Path("test.py")


def analyze(source):
    tree = ast.parse(source)
    return RULE.check(tree, FILE)


def test_detects_hardcoded_password():
    findings = analyze(
        """
PASSWORD = "MySuperSecret123"
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"
    assert findings[0].severity.value == "high"


def test_detects_hardcoded_api_key():
    findings = analyze(
        """
API_KEY = "sk_live_123456789abcdef"
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"


def test_detects_hardcoded_token():
    findings = analyze(
        """
AUTH_TOKEN = "very-long-secret-token-value"
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"


def test_detects_aws_access_key():
    findings = analyze(
        """
value = "AKIA1234567890ABCDEF"
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"


def test_detects_jwt():
    findings = analyze(
        """
TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"


def test_detects_private_key():
    findings = analyze(
        '''
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
secret-data
-----END PRIVATE KEY-----"""
'''
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"


def test_ignores_password_field_name():
    findings = analyze(
        """
PASSWORD_FIELD = "password"
"""
    )

    assert len(findings) == 0


def test_ignores_api_version():
    findings = analyze(
        """
API_VERSION = "v1"
"""
    )

    assert len(findings) == 0


def test_ignores_token_expiry():
    findings = analyze(
        """
TOKEN_EXPIRY = "3600"
"""
    )

    assert len(findings) == 0


def test_ignores_placeholder_secret():
    findings = analyze(
        """
SECRET_KEY = "changeme"
"""
    )

    assert len(findings) == 0


def test_ignores_dynamic_secret():
    findings = analyze(
        """
SECRET_KEY = os.getenv("SECRET_KEY")
"""
    )

    assert len(findings) == 0


def test_ignores_non_secret_constant():
    findings = analyze(
        """
COMPANY_NAME = "Darul Madinah"
"""
    )

    assert len(findings) == 0

def test_ignores_secret_like_name_with_normal_value():
    findings = analyze(
        """
WEBHOOK_SECRET_HEADER = "X-Webhook-Secret"
"""
    )

    assert len(findings) == 0


def test_ignores_token_type_hint():
    findings = analyze(
        """
TOKEN_TYPE_HINT = "access_token"
"""
    )

    assert len(findings) == 0


def test_detects_strong_secret_value():
    findings = analyze(
        """
API_KEY = "Abc123$VerySecretKey!"
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC004"


def test_ignores_short_secret_value():
    findings = analyze(
        """
API_KEY = "abc123"
"""
    )

    assert len(findings) == 0