"""Programmatic corpus expansion for whitepaper benchmarks.

Generates additional true-positive, benign, and adversarial samples
to expand the benchmark corpus from ~400 to ~1500+ samples for
tighter Clopper-Pearson confidence intervals.
"""

import base64 as _b64
import hashlib
import string

# ---------------------------------------------------------------------------
# Prefix variables (must match test_whitepaper_benchmarks.py)
# ---------------------------------------------------------------------------
_SLACK_PFX = "xox"
_SLACK_BODY = "1234567890123456789012345678901234567890"
_SK_LIVE = "sk_" + "live_"
_SK_TEST = "sk_" + "test_"
_RK_LIVE = "rk_" + "live_"
_STRIPE_BODY = "FAKEFAKEFAKEFAKEFAKEFAKE"
_AWS_PFX = "AKI" + "A"
_GH_P = "gh" + "p_"
_GH_O = "gh" + "o_"
_GH_S = "gh" + "s_"
_GH_R = "gh" + "r_"


def _deterministic_alnum(seed: str, length: int, charset: str = "") -> str:
    """Generate a deterministic alphanumeric string from a seed."""
    if not charset:
        charset = string.ascii_letters + string.digits
    h = hashlib.sha256(seed.encode()).hexdigest() * ((length // 64) + 2)
    result = []
    for i, c in enumerate(h):
        if len(result) >= length:
            break
        idx = int(c, 16) + i
        result.append(charset[idx % len(charset)])
    return "".join(result)


def _deterministic_upper_alnum(seed: str, length: int) -> str:
    """Generate deterministic uppercase alphanumeric string for AWS keys."""
    return _deterministic_alnum(seed, length, string.ascii_uppercase + string.digits)


def generate_additional_aws_keys(count: int = 80) -> list[str]:
    """Generate additional AWS access key IDs: AKIA + 16 [0-9A-Z] chars."""
    keys = []
    for i in range(count):
        suffix = _deterministic_upper_alnum(f"aws_extra_{i}", 16)
        keys.append(_AWS_PFX + suffix)
    return keys


def generate_additional_github_tokens(count: int = 80) -> list[str]:
    """Generate additional GitHub tokens with mixed prefixes."""
    prefixes = [_GH_P, _GH_O, _GH_S, _GH_R]
    tokens = []
    for i in range(count):
        prefix = prefixes[i % 4]
        body = _deterministic_alnum(f"gh_extra_{i}", 36)
        tokens.append(prefix + body)
    return tokens


def generate_additional_slack_tokens(count: int = 80) -> list[str]:
    """Generate additional Slack tokens with mixed type prefixes."""
    types = ["b-", "p-", "a-", "r-", "s-"]
    tokens = []
    for i in range(count):
        t = types[i % 5]
        body = _deterministic_alnum(f"slack_extra_{i}", 40)
        tokens.append(_SLACK_PFX + t + body)
    return tokens


def generate_additional_stripe_keys(count: int = 80) -> list[str]:
    """Generate additional Stripe keys with mixed prefixes."""
    prefixes = [_SK_LIVE, _SK_TEST, _RK_LIVE]
    keys = []
    for i in range(count):
        prefix = prefixes[i % 3]
        body = _deterministic_alnum(f"stripe_extra_{i}", 24)
        keys.append(prefix + body)
    return keys


def generate_additional_jwt_tokens(count: int = 80) -> list[str]:
    """Generate additional JWT tokens with varied headers and payloads."""
    algos = [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9",
        "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9",
        "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9",
        "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9",
    ]
    payloads = [
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
        "eyJ1c2VyIjoiYWRtaW4ifQ",
        "eyJyb2xlIjoic3VwZXIifQ",
        "eyJpc3MiOiJ0ZXN0In0",
        "eyJhdWQiOiJhcGkifQ",
        "eyJleHAiOjE3MTYwMDAwMDB9",
        "eyJpYXQiOjE3MDAwMDAwMDB9",
        "eyJqdGkiOiJ1bmlxdWUxMjMifQ",
        "eyJzY29wZSI6InJlYWQifQ",
        "eyJlbWFpbCI6InRlc3RAdGVzdC5jb20ifQ",
    ]
    tokens = []
    for i in range(count):
        header = algos[i % len(algos)]
        payload = payloads[i % len(payloads)]
        sig = _deterministic_alnum(f"jwt_sig_{i}", 20, string.ascii_letters + string.digits + "_-")
        tokens.append(f"{header}.{payload}.{sig}")
    return tokens


def generate_additional_private_keys(count: int = 80) -> list[str]:
    """Generate additional private key blocks."""
    types = [
        ("RSA PRIVATE KEY", "MIIEpAIBAAKCAQEA"),
        ("EC PRIVATE KEY", "MHQCAQEEIOYz1AbCdEf"),
        ("OPENSSH PRIVATE KEY", "b3BlbnNzaC1rZXktdjEAAAA"),
        ("PGP PRIVATE KEY BLOCK", "Version: GnuPG v2\nmQINBGRh"),
        ("RSA PRIVATE KEY", "MIIBogIBAAJBANv4TuVw"),
        ("RSA PRIVATE KEY", "MIICXQIBAAJBAMfakeKey"),
        ("EC PRIVATE KEY", "MHQCAQEEIKwXyZaBcDeFg"),
        ("RSA PRIVATE KEY", "MIIEvgIBAAKCAQEA3mNoPqR"),
    ]
    keys = []
    for i in range(count):
        key_type, body_prefix = types[i % len(types)]
        unique = _deterministic_alnum(
            f"pk_extra_{i}", 20, string.ascii_letters + string.digits + "/+"
        )
        if key_type == "PGP PRIVATE KEY BLOCK":
            keys.append(
                f"-----BEGIN {key_type}-----\n{body_prefix}{unique}\n-----END {key_type}-----"
            )
        else:
            keys.append(
                f"-----BEGIN {key_type}-----\n{body_prefix}{unique}\n-----END {key_type}-----"
            )
    return keys


def generate_additional_database_urls(count: int = 80) -> list[str]:
    """Generate additional database connection URLs."""
    schemes = ["postgresql", "mysql", "mongodb", "redis"]
    users = [
        "admin",
        "root",
        "deploy",
        "webapp",
        "service",
        "readonly",
        "etl",
        "api",
        "backup",
        "worker",
    ]
    hosts = [
        "db.example.com",
        "mysql.internal",
        "mongo.cluster.local",
        "redis.internal",
        "pg.us-east-1.rds.amazonaws.com",
        "mysql-primary.prod",
        "mongo-rs0.example.com",
        "redis-sentinel.internal",
        "warehouse.rds.amazonaws.com",
        "db-replica.internal",
        "pg-staging.internal",
        "mysql-batch.internal",
        "mongo-atlas.example.com",
        "redis-pubsub.internal",
        "pg-primary.internal",
    ]
    databases = [
        "mydb",
        "production",
        "staging",
        "analytics",
        "reporting",
        "users",
        "sessions",
        "cache",
        "app",
        "api",
    ]
    urls = []
    for i in range(count):
        scheme = schemes[i % 4]
        user = users[i % len(users)]
        host = hosts[i % len(hosts)]
        db = databases[i % len(databases)]
        pwd = _deterministic_alnum(f"dbpwd_{i}", 12, string.ascii_letters + string.digits + "!@#")
        port = {"postgresql": 5432, "mysql": 3306, "mongodb": 27017, "redis": 6379}[scheme]
        urls.append(f"{scheme}://{user}:{pwd}@{host}:{port}/{db}")
    return urls


def generate_additional_passwords(count: int = 80) -> list[str]:
    """Generate additional password patterns."""
    patterns = [
        "password=",
        "passwd: ",
        'pwd = "',
        "PASSWORD=",
        "password: ",
        "passwd=",
        'pwd = "',
        "password =",
    ]
    passwords = []
    for i in range(count):
        pattern = patterns[i % len(patterns)]
        value = _deterministic_alnum(
            f"passwd_{i}", 16, string.ascii_letters + string.digits + "!@#$"
        )
        if pattern.endswith('"'):
            passwords.append(f'{pattern}{value}"')
        else:
            passwords.append(f"{pattern}{value}")
    return passwords


def generate_additional_api_keys(count: int = 80) -> list[str]:
    """Generate additional API key patterns."""
    patterns = [
        "api_key=",
        "access_token: ",
        'apikey = "',
        "API_KEY=",
        "api-key: ",
        "api_key=",
        "access_token: ",
        'apikey = "',
    ]
    prefixes = [
        "sk_proj_",
        "tkn_",
        "key_",
        "prod_",
        "live_",
        "svc_",
        "pat_",
        "dev_key_",
        "stg_",
        "bearer_",
    ]
    keys = []
    for i in range(count):
        pattern = patterns[i % len(patterns)]
        prefix = prefixes[i % len(prefixes)]
        body = _deterministic_alnum(f"apikey_{i}", 24)
        value = prefix + body
        if pattern.endswith('"'):
            keys.append(f'{pattern}{value}"')
        else:
            keys.append(f"{pattern}{value}")
    return keys


def generate_all_additional_tp() -> dict[str, list[str]]:
    """Generate all additional true-positive secrets."""
    return {
        "aws_key": generate_additional_aws_keys(),
        "github_token": generate_additional_github_tokens(),
        "slack_token": generate_additional_slack_tokens(),
        "stripe_key": generate_additional_stripe_keys(),
        "jwt_token": generate_additional_jwt_tokens(),
        "private_key": generate_additional_private_keys(),
        "database_url": generate_additional_database_urls(),
        "password": generate_additional_passwords(),
        "api_key": generate_additional_api_keys(),
    }


# ---------------------------------------------------------------------------
# Additional adversarial secrets
# ---------------------------------------------------------------------------


def generate_additional_adversarial() -> dict[str, list[str]]:
    """Generate additional adversarial secret samples."""
    return {
        "base64_encoded": [
            _b64.b64encode((_AWS_PFX + "FAKE12345678FAKE").encode()).decode(),
            _b64.b64encode(
                b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            ).decode(),
            _b64.b64encode((_GH_P + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8").encode()).decode(),
            _b64.b64encode((_GH_O + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8").encode()).decode(),
            _b64.b64encode((_GH_S + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8").encode()).decode(),
            _b64.b64encode((_GH_R + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8").encode()).decode(),
            _b64.b64encode((_SLACK_PFX + "b-" + _SLACK_BODY).encode()).decode(),
            _b64.b64encode((_SLACK_PFX + "p-" + _SLACK_BODY).encode()).decode(),
            _b64.b64encode((_SK_LIVE + _STRIPE_BODY).encode()).decode(),
            _b64.b64encode((_SK_TEST + _STRIPE_BODY).encode()).decode(),
            _b64.b64encode((_RK_LIVE + _STRIPE_BODY).encode()).decode(),
            _b64.b64encode(
                b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
            ).decode(),
            _b64.b64encode(
                b"postgresql://admin:SuperS3cretP@ss!@db.example.com:5432/production"
            ).decode(),
            _b64.b64encode(
                b"mongodb+srv://root:hunter2password@cluster0.abc123.mongodb.net/mydb"
            ).decode(),
            _b64.b64encode(("Authorization: Bearer " + _SK_LIVE + _STRIPE_BODY).encode()).decode(),
            _b64.b64encode(b'PASSWORD="Tr0ub4dor&3_c0rrect_h0rse"').decode(),
            _b64.b64encode(_b64.b64encode((_AWS_PFX + "FAKE12345678FAKE").encode())).decode(),
            _b64.b64encode(_b64.b64encode((_SK_LIVE + _STRIPE_BODY).encode())).decode(),
            _b64.b64encode(
                _b64.b64encode((_GH_P + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8").encode())
            ).decode(),
            _b64.b64encode(
                b"mysql://deploy_user:z9kLmN3pQ7rS@mysql.internal:3306/app_prod"
            ).decode(),
            _b64.b64encode(b"redis://:p4ssw0rd_f0r_r3dis@redis.example.com:6379/0").decode(),
            _b64.b64encode(b"api_key=prod_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd").decode(),
            _b64.b64encode(
                b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn"
            ).decode(),
            _b64.b64encode(b"access_token: bearer_ABCDEFGHIJKLMNOPQRSTUVWXYZab").decode(),
        ],
        "split_secrets": [
            _AWS_PFX + "FAKE" + "1234" + "5678FAKE",
            _GH_P + "A1b2C3d4" + "E5f6G7h8" + "I9j0K1l2" + "M3n4O5p6Q7r8",
            _GH_O + "abcdefghij" + "klmnopqrstuvwxyz" + "0123456789",
            _GH_S + "aaaa" + "bbbb" + "cccc" + "dddd" + "eeee" + "ffff" + "gggg" + "hhhh" + "iiii",
            _GH_R + "zZ" * 9 + "yY" * 9,
            _SLACK_PFX + "b" + "-" + _SLACK_BODY,
            "".join([_SLACK_PFX, "p-", _SLACK_BODY]),
            _SK_LIVE + "FAKEFAKE" + "FAKEFAKE" + "FAKEFAKE",
            _SK_TEST + "ABCDEFGH" + "IJKLMNOP" + "QRSTUVWX",
            _RK_LIVE + "aabbccdd" + "eeffgghh" + "iijjkkll",
            "sk" + "_" + "live" + "_" + "FAKEFAKEFAKEFAKEFAKEFAKE",
            "postgresql://"
            + "admin"
            + ":"
            + "S3cretP@ssw0rd"
            + "@"
            + "db.prod.internal"
            + ":5432/appdb",
            "mongodb+srv://" + "root" + ":" + "hunt3r2p@ss" + "@cluster0.abc.mongodb.net/db",
            "eyJhbGciOiJIUzI1NiJ9"
            + "."
            + "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            + "."
            + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "redis://:r3d1s_p4ss" + "@" + "cache.internal:6379/0",
            f"{_AWS_PFX}VOGT{'NOACCESS'}DEMO",
            f"{_AWS_PFX}{'ZZZZ1234ZZZZZZZZ'}",
            f"{_SLACK_PFX}b-{_SLACK_BODY}",
            "".join([_GH_P, "Zx9Yw8Xv", "7Wu6Vt5Us", "4Tr3Sq2Rp", "1On0Nm"]),
            _SK_LIVE + "".join(["F", "A", "K", "E"] * 6),
            _GH_O + "part1abc" + "part2def" + "part3ghi" + "part4jkl" + "mn",
            "password" + "=" + "Sup3rL0ngP4ssw0rd!",
            "api_key" + "=" + "prod_AbCdEfGhIjKlMnOpQrStUvWx",
            _AWS_PFX + "TEST" + "CRED" + "VALI" + "DATE",
            _GH_P + "Split" + "Token" + "Test" + "Value" + "For" + "Bench" + "mark1",
        ],
        "multiline_context": [
            "aws:\n  region: us-east-1\n  access_key_id: "
            + _AWS_PFX
            + "FAKE12345678FAKE\n  secret_access_key: wJalrXUtnFEMI/K7MDENG",
            "# Production environment\nSTRIPE_SECRET_KEY="
            + _SK_LIVE
            + _STRIPE_BODY
            + "\nDATABASE_URL=postgres://localhost/mydb",
            "#!/bin/bash\nset -e\nexport GITHUB_TOKEN="
            + _GH_P
            + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
            + "\ngit clone https://$GITHUB_TOKEN@github.com/org/repo.git",
            "FROM python:3.12-slim\nENV SLACK_BOT_TOKEN="
            + _SLACK_PFX
            + "b-"
            + _SLACK_BODY
            + "\nRUN pip install slack-sdk",
            "name: Deploy\non: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    env:\n      AWS_ACCESS_KEY_ID: "
            + _AWS_PFX
            + "FAKE12345678FAKE",
            "stages:\n  - deploy\ndeploy_prod:\n  variables:\n    STRIPE_KEY: "
            + _SK_LIVE
            + _STRIPE_BODY
            + "\n  script:\n    - ./deploy.sh",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: api-creds\nstringData:\n  github-token: "
            + _GH_P
            + "K9j8H7g6F5e4D3c2B1a0Z9y8X7w6V5u4T3s2",
            'provider "aws" {\n  region     = "us-west-2"\n  access_key = "'
            + _AWS_PFX
            + 'FAKE12345678FAKE"\n}',
            "[credentials]\naws_access_key_id = "
            + _AWS_PFX
            + "FAKE12345678FAKE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG",
            'server {\n  listen 443 ssl;\n  location /api {\n    proxy_set_header Authorization "Bearer '
            + _SK_LIVE
            + _STRIPE_BODY
            + '";\n  }\n}',
            "version: '3.8'\nservices:\n  app:\n    environment:\n      - SLACK_TOKEN="
            + _SLACK_PFX
            + "b-"
            + _SLACK_BODY
            + "\n      - STRIPE_KEY="
            + _SK_LIVE
            + _STRIPE_BODY,
            "- name: Configure app\n  hosts: webservers\n  vars:\n    api_token: "
            + _GH_O
            + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            'variable "stripe_key" {\n  default = "'
            + _SK_TEST
            + _STRIPE_BODY
            + '"\n  sensitive = true\n}',
            "replicaCount: 3\nsecrets:\n  awsAccessKeyId: "
            + _AWS_PFX
            + "FAKE12345678FAKE\n  slackWebhookToken: "
            + _SLACK_PFX
            + "b-"
            + _SLACK_BODY,
            "version: 2.1\njobs:\n  build:\n    environment:\n      GITHUB_TOKEN: "
            + _GH_P
            + "M1n2O3p4Q5r6S7t8U9v0W1x2Y3z4A5b6C7d8",
            "config:\n  aws:region: us-east-1\n  app:stripeSecretKey: " + _SK_LIVE + _STRIPE_BODY,
            "import os\nDATABASE_URL = 'postgresql://admin:s3cretDbP4ss@db.prod:5432/app'\nSLACK_BOT_TOKEN = '"
            + _SLACK_PFX
            + "b-"
            + _SLACK_BODY
            + "'",
            '{\n  "production": {\n    "aws_access_key": "'
            + _AWS_PFX
            + 'FAKE12345678FAKE",\n    "stripe_key": "'
            + _SK_LIVE
            + _STRIPE_BODY
            + '"\n  }\n}',
            '[tool.myapp]\nslack_token = "'
            + _SLACK_PFX
            + "b-"
            + _SLACK_BODY
            + '"\nstripe_key = "'
            + _SK_TEST
            + _STRIPE_BODY
            + '"',
            "DEPLOY_TOKEN := "
            + _GH_P
            + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"
            + '\n\n.PHONY: deploy\ndeploy:\n\tcurl -H "Authorization: token $(DEPLOY_TOKEN)"',
            '[Service]\nType=simple\nEnvironment="GITHUB_TOKEN='
            + _GH_P
            + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
            + '"\nExecStart=/usr/bin/myapp',
            "# Deployment credentials\nstripeApiKey="
            + _SK_LIVE
            + _STRIPE_BODY
            + "\ngithubPackagesToken="
            + _GH_P
            + "T1u2V3w4X5y6Z7a8B9c0D1e2F3g4H5i6J7k8",
            "[default]\naws_access_key_id = "
            + _AWS_PFX
            + "FAKE12345678FAKE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG\n\n[staging]\naws_access_key_id = "
            + _AWS_PFX
            + "STAG12345678STAG",
        ],
        "unicode_homoglyphs": [
            "AKI\u0410FAKE12345678FAKE",
            "x\u043exb-" + _SLACK_BODY,
            "gh\u0440_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "\u0441k_live_" + _STRIPE_BODY,
            "x\u03bfxb-" + _SLACK_BODY,
            "sk_t\u0435st_" + _STRIPE_BODY,
            "A\u041aIA" + "FAKE12345678FAKE",
            "gh\u200bp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "sk_\u200clive_" + _STRIPE_BODY,
            "xox\u200bb-" + _SLACK_BODY,
            "\u0445oxb-" + _SLACK_BODY,
            "\uff53k_live_" + _STRIPE_BODY,
            "\uff47hp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "\uff21KIA" + "FAKE12345678FAKE",
            "\u0410\u041aIAFAKE12345678FAKE",
            "p\u03b1ssword=MyS3cretP4ssw0rd!",
            "A\u200bK\u200bI\u200bA" + "FAKE12345678FAKE",
            "postgresql://admin:s\u0443perSecret@db.example.com:5432/prod",
            "eyJhbGciOiJIUzI1NiIsIn\u0422pcCI6IkpXVCJ9.eyJzdWIiOiIxIn0.fake",
            "xox\u0432-" + _SLACK_BODY,
            "s\uff4b_live_" + _STRIPE_BODY,
            "\u0420ASSWORD=hunter2_f4ke_p4ss_v3ry_l0ng",
            "\uff58oxb-" + _SLACK_BODY,
            "gh\u0441_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "xo\u0425b-" + _SLACK_BODY,
        ],
    }


# ---------------------------------------------------------------------------
# Additional benign texts
# ---------------------------------------------------------------------------


def generate_additional_benign() -> dict[str, list[str]]:
    """Generate additional benign text samples for FP testing."""
    return {
        "prose": [
            "The event-driven architecture allows services to communicate asynchronously through message queues.",
            "Infrastructure as Code enables version-controlled, repeatable deployments across environments.",
            "The circuit breaker pattern prevents cascading failures in distributed microservice architectures.",
            "Observability encompasses three pillars: structured logging, distributed tracing, and metrics.",
            "Zero-trust security models require verification of every request regardless of network location.",
            "Container orchestration platforms manage scaling, health checks, and rolling updates automatically.",
            "The CQRS pattern separates read and write operations for optimized query and command handling.",
            "Feature toggles enable trunk-based development by hiding incomplete features behind flags.",
            "Immutable infrastructure replaces servers rather than modifying them, ensuring consistency.",
            "Service meshes provide observability, traffic management, and security between microservices.",
            "The twelve-factor app methodology defines best practices for building cloud-native applications.",
            "Chaos engineering proactively tests system resilience by injecting controlled failures.",
            "GitOps uses Git as the single source of truth for declarative infrastructure and applications.",
            "Blue-green deployments maintain two identical environments to enable instant rollback.",
            "The strangler fig pattern gradually migrates legacy systems to new architectures.",
            "Event sourcing stores state changes as an immutable sequence of domain events.",
            "Distributed consensus algorithms like Raft ensure data consistency across replicated nodes.",
            "The saga pattern manages distributed transactions across multiple microservices.",
            "Content delivery networks cache static assets at edge locations to reduce latency.",
            "Progressive delivery combines feature flags, canary releases, and blue-green deployments.",
            "Database connection pooling reduces the overhead of creating new database connections.",
            "The sidecar pattern deploys auxiliary components alongside the main application container.",
            "Rate limiting protects services from being overwhelmed by too many concurrent requests.",
            "Distributed tracing correlates requests across service boundaries using trace identifiers.",
            "The bulkhead pattern isolates elements of an application to prevent cascading failures.",
            "Schema migrations should be backward-compatible to support zero-downtime deployments.",
            "The outbox pattern ensures reliable event publishing from database transactions.",
            "API versioning strategies include URL path, query parameter, and header-based approaches.",
            "Health check endpoints allow orchestrators to determine service readiness and liveness.",
            "The ambassador pattern offloads common connectivity tasks like retries and circuit breaking.",
            "Kubernetes horizontal pod autoscaler adjusts replica counts based on CPU or custom metrics.",
            "Data partitioning strategies include hash-based, range-based, and geographic partitioning.",
            "The retry pattern with exponential backoff prevents thundering herd problems during recovery.",
            "Idempotent operations ensure that repeating a request produces the same result.",
            "Multi-region deployment strategies balance latency, cost, and disaster recovery needs.",
            "The competing consumers pattern distributes work items across multiple parallel workers.",
            "Structured logging with correlation IDs enables end-to-end request tracing across services.",
            "Configuration management tools ensure consistent system state across server fleets.",
            "The anti-corruption layer pattern protects a domain model from external system influences.",
            "Deployment pipelines automate the process from code commit to production release.",
        ],
        "code": [
            "async def process_batch(items: list[dict]) -> list[Result]:\n    tasks = [process_item(item) for item in items]\n    return await asyncio.gather(*tasks)",
            "class RateLimiter:\n    def __init__(self, max_requests: int, window_seconds: int):\n        self.max_requests = max_requests\n        self.window = window_seconds\n        self._requests: dict[str, list[float]] = {}",
            "def exponential_backoff(attempt: int, base: float = 0.5, max_delay: float = 30.0) -> float:\n    delay = min(base * (2 ** attempt), max_delay)\n    return delay + random.uniform(0, delay * 0.1)",
            "from dataclasses import dataclass, field\nfrom datetime import datetime\n\n@dataclass\nclass AuditEvent:\n    timestamp: datetime = field(default_factory=datetime.now)\n    action: str = ''\n    resource: str = ''",
            "class CircuitBreaker:\n    CLOSED, OPEN, HALF_OPEN = range(3)\n    def __init__(self, threshold: int = 5, timeout: float = 60.0):\n        self.state = self.CLOSED\n        self.failure_count = 0",
            "def validate_config(config: dict) -> list[str]:\n    errors = []\n    if 'host' not in config:\n        errors.append('Missing required field: host')\n    if config.get('port', 0) < 1:\n        errors.append('Port must be positive')\n    return errors",
            "async with aiohttp.ClientSession() as session:\n    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:\n        if resp.status == 200:\n            return await resp.json()",
            "type Result[T] = { success: true; data: T } | { success: false; error: string };\n\nfunction ok<T>(data: T): Result<T> { return { success: true, data }; }",
            'const router = express.Router();\nrouter.get("/users/:id", async (req, res) => {\n  const user = await db.users.findById(req.params.id);\n  res.json(user ?? { error: "not found" });\n});',
            "func worker(ctx context.Context, jobs <-chan Job, results chan<- Result) {\n    for {\n        select {\n        case job := <-jobs:\n            results <- process(job)\n        case <-ctx.Done():\n            return\n        }\n    }\n}",
            "fn parse_config(path: &Path) -> Result<Config, ConfigError> {\n    let contents = fs::read_to_string(path)?;\n    let config: Config = toml::from_str(&contents)?;\n    config.validate()?;\n    Ok(config)\n}",
            'pub async fn health_check(pool: &PgPool) -> Result<StatusCode, AppError> {\n    sqlx::query("SELECT 1").execute(pool).await?;\n    Ok(StatusCode::OK)\n}',
            "@app.middleware('http')\nasync def add_correlation_id(request, call_next):\n    request.state.correlation_id = str(uuid4())\n    response = await call_next(request)\n    response.headers['X-Correlation-ID'] = request.state.correlation_id\n    return response",
            "const { data, error, isLoading } = useSWR(\n  `/api/users/${userId}`,\n  fetcher,\n  { revalidateOnFocus: false, dedupingInterval: 5000 }\n);",
            "impl<T: Send + Sync> Pool<T> {\n    pub async fn acquire(&self) -> PoolGuard<T> {\n        let conn = self.idle.lock().await.pop_front()\n            .unwrap_or_else(|| self.create_new());\n        PoolGuard { conn, pool: self }\n    }\n}",
            "SELECT\n  date_trunc('hour', created_at) AS hour,\n  COUNT(*) AS requests,\n  AVG(duration_ms) AS avg_duration,\n  PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95\nFROM access_logs\nWHERE created_at > NOW() - INTERVAL '24 hours'\nGROUP BY 1\nORDER BY 1;",
            'resource "aws_lambda_function" "handler" {\n  function_name = "event-handler"\n  runtime       = "python3.12"\n  handler       = "main.handler"\n  memory_size   = 256\n  timeout       = 30\n}',
            "def retry(max_attempts=3, backoff_factor=2):\n    def decorator(func):\n        @wraps(func)\n        async def wrapper(*args, **kwargs):\n            for attempt in range(max_attempts):\n                try:\n                    return await func(*args, **kwargs)\n                except Exception:\n                    if attempt == max_attempts - 1:\n                        raise\n                    await asyncio.sleep(backoff_factor ** attempt)\n        return wrapper\n    return decorator",
            "class MetricsCollector:\n    def __init__(self):\n        self._counters: dict[str, int] = defaultdict(int)\n        self._histograms: dict[str, list[float]] = defaultdict(list)\n\n    def increment(self, name: str, value: int = 1) -> None:\n        self._counters[name] += value",
            "#!/usr/bin/env python3\nimport argparse\n\ndef main():\n    parser = argparse.ArgumentParser(description='Deploy application')\n    parser.add_argument('--env', choices=['dev', 'staging', 'prod'], required=True)\n    parser.add_argument('--version', type=str, required=True)\n    args = parser.parse_args()\n    deploy(args.env, args.version)",
            "interface Repository<T, ID> {\n  findById(id: ID): Promise<T | null>;\n  findAll(options?: PaginationOptions): Promise<PaginatedResult<T>>;\n  save(entity: T): Promise<T>;\n  delete(id: ID): Promise<void>;\n}",
            "CREATE TABLE IF NOT EXISTS events (\n  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),\n  event_type VARCHAR(100) NOT NULL,\n  payload JSONB NOT NULL DEFAULT '{}',\n  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\n  processed_at TIMESTAMPTZ\n);\nCREATE INDEX idx_events_type_created ON events (event_type, created_at);",
            ".PHONY: all test lint build clean\n\nall: lint test build\n\ntest:\n\tpytest tests/ -v --tb=short\n\nlint:\n\truff check src/ tests/\n\truff format --check src/ tests/\n\nbuild:\n\tdocker build -t myapp:$(shell git rev-parse --short HEAD) .",
            'fn main() {\n    let config = Config::from_env().expect("Failed to load config");\n    let runtime = tokio::runtime::Builder::new_multi_thread()\n        .worker_threads(config.workers)\n        .enable_all()\n        .build()\n        .expect("Failed to create runtime");\n    runtime.block_on(serve(config));\n}',
            'Map<String, List<Event>> grouped = events.stream()\n    .filter(e -> e.getTimestamp().isAfter(cutoff))\n    .collect(Collectors.groupingBy(Event::getType));\ngrouped.forEach((type, list) -> log.info("{}: {} events", type, list.size()));',
            "class Config(BaseModel):\n    host: str = '0.0.0.0'\n    port: int = 8080\n    workers: int = 4\n    debug: bool = False\n    db_pool_size: int = 10\n    cache_ttl: int = 3600\n\n    model_config = ConfigDict(env_prefix='APP_')",
            "const pipeline = [\n  { $match: { status: 'active', createdAt: { $gte: startDate } } },\n  { $group: { _id: '$category', total: { $sum: '$amount' }, count: { $sum: 1 } } },\n  { $sort: { total: -1 } },\n  { $limit: 10 }\n];",
            "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: cleanup\nspec:\n  schedule: '0 2 * * *'\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n          - name: cleanup\n            image: myapp:latest\n            command: ['python', '-m', 'tasks.cleanup']",
            "{ pkgs ? import <nixpkgs> {} }:\npkgs.mkShell {\n  buildInputs = with pkgs; [ python312 poetry nodejs_20 ];\n  shellHook = ''export PYTHONDONTWRITEBYTECODE=1'';\n}",
            "pub struct ConnectionPool {\n    connections: Vec<Connection>,\n    max_size: usize,\n    timeout: Duration,\n}\n\nimpl ConnectionPool {\n    pub fn new(max_size: usize) -> Self {\n        Self { connections: Vec::new(), max_size, timeout: Duration::from_secs(30) }\n    }\n}",
            "type PaginatedResponse<T> = {\n  data: T[];\n  total: number;\n  page: number;\n  pageSize: number;\n  hasNext: boolean;\n};",
            'for i in $(seq 1 30); do\n  curl -sf "http://localhost:8080/health" && exit 0\n  sleep 1\ndone\nexit 1',
            'public record ApiResponse<T>(int status, String message, T data) {\n    public static <T> ApiResponse<T> ok(T data) {\n        return new ApiResponse<>(200, "success", data);\n    }\n}',
            "WITH daily AS (\n  SELECT date_trunc('day', ts) AS day, COUNT(*) AS cnt\n  FROM events WHERE ts > NOW() - '30 days'::interval\n  GROUP BY 1\n)\nSELECT day, cnt, AVG(cnt) OVER (ORDER BY day ROWS 6 PRECEDING) AS rolling_avg\nFROM daily;",
            '@Bean\npublic SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n    return http\n        .csrf(AbstractHttpConfigurer::disable)\n        .authorizeHttpRequests(auth -> auth\n            .requestMatchers("/health").permitAll()\n            .anyRequest().authenticated())\n        .build();\n}',
            "async fn fetch_with_retry(url: &str, retries: u32) -> Result<Response, reqwest::Error> {\n    let client = reqwest::Client::new();\n    for _ in 0..retries {\n        if let Ok(resp) = client.get(url).send().await {\n            return Ok(resp);\n        }\n        tokio::time::sleep(Duration::from_millis(500)).await;\n    }\n    client.get(url).send().await\n}",
            'syntax = "proto3";\n\nservice UserService {\n  rpc GetUser (GetUserRequest) returns (User);\n  rpc ListUsers (ListUsersRequest) returns (stream User);\n}\n\nmessage User {\n  string id = 1;\n  string name = 2;\n}',
            "const useDebounce = <T>(value: T, delay: number): T => {\n  const [debounced, setDebounced] = useState(value);\n  useEffect(() => {\n    const timer = setTimeout(() => setDebounced(value), delay);\n    return () => clearTimeout(timer);\n  }, [value, delay]);\n  return debounced;\n};",
            ".container {\n  display: grid;\n  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));\n  gap: 1.5rem;\n  padding: 2rem;\n}",
            "CompletableFuture<List<Order>> future = CompletableFuture\n    .supplyAsync(() -> orderRepository.findByCustomerId(customerId))\n    .thenApply(orders -> orders.stream()\n        .filter(o -> o.getStatus() == Status.ACTIVE)\n        .toList());",
        ],
        "logs": [
            "2024-03-22 14:05:12.789 INFO [scheduler] Cron job cleanup_stale_sessions completed in 234ms",
            "2024-03-22 14:05:13.012 DEBUG [connection-pool] Acquired connection 7 of 20 from pool db-primary",
            "2024-03-22 14:05:14.456 WARN [circuit-breaker] Circuit for payment-service opened after 5 failures",
            "2024-03-22 14:05:15.678 ERROR [grpc-server] Stream terminated: status=UNAVAILABLE peer=10.0.3.42:50051",
            "2024-03-22 14:05:16.890 INFO [migration] Applied migration 20240322_add_index in 3.2s",
            "2024-03-22 14:05:17.123 DEBUG [cache] LRU eviction: removed 512 entries, current size 9488/10000",
            "2024-03-22 14:05:18.234 INFO [deployer] Rolling update: 3/5 pods updated, 2 pending",
            "2024-03-22 14:05:19.456 WARN [rate-limiter] Client 10.0.1.200 approaching rate limit: 92/100",
            "2024-03-22 14:05:20.678 ERROR [websocket] Connection closed: code=1006 reason=abnormal_closure",
            "2024-03-22 14:05:21.890 INFO [metrics] Flushed 4200 metric points to backend in 89ms",
            '{"ts":"2024-03-22T14:06:00Z","level":"info","caller":"server/main.go:42","msg":"listening","addr":":8080"}',
            '{"ts":"2024-03-22T14:06:01Z","level":"warn","caller":"pool/conn.go:118","msg":"connection reset","remote":"10.0.2.50:5432"}',
            '{"ts":"2024-03-22T14:06:02Z","level":"info","caller":"handler/order.go:85","msg":"order created","order_id":"ord_7f8a9b2c"}',
            '{"ts":"2024-03-22T14:06:03Z","level":"debug","caller":"cache/redis.go:67","msg":"pipeline executed","commands":12}',
            '{"ts":"2024-03-22T14:06:04Z","level":"error","caller":"worker/process.go:201","msg":"job failed","job_id":"job_4e5f6a7b"}',
            '{"ts":"2024-03-22T14:06:05Z","level":"info","caller":"auth/middleware.go:33","msg":"session validated","user":"admin"}',
            '{"ts":"2024-03-22T14:06:06Z","level":"info","caller":"kafka/consumer.go:91","msg":"partition rebalanced","topic":"events"}',
            '{"ts":"2024-03-22T14:06:07Z","level":"warn","caller":"dns/resolver.go:55","msg":"slow DNS","host":"api.vendor.com","ms":1250}',
            "Mar 22 14:07:00 k8s-node01 kubelet[1234]: Syncing pod uid=a1b2c3d4",
            "Mar 22 14:07:01 k8s-node01 containerd[5678]: starting container id=abc123def",
            "Mar 22 14:07:02 gateway01 envoy[9012]: upstream connect 10.0.4.100:8080 cluster=api-backend",
            "Mar 22 14:07:03 db01 postgres[3456]: LOG: autovacuum launcher started on database main",
            "Mar 22 14:07:04 queue01 rabbitmq[6789]: msg store compacted 1024 entries in 0.3s",
            "Mar 22 14:07:05 vault01 vault[2345]: seal-status: sealed=false cluster=vault-prod",
            "Mar 22 14:07:06 proxy01 nginx[8901]: upstream timed out while reading response header",
            "Mar 22 14:07:07 build01 buildkitd[4567]: resolve docker.io/library/python:3.12-slim done",
            '10.0.1.100 - - [22/Mar/2024:14:08:00 +0000] "GET /api/v3/metrics HTTP/2" 200 4521',
            '10.0.1.101 - - [22/Mar/2024:14:08:01 +0000] "POST /api/v3/events HTTP/2" 202 0',
            "Event: pod/api-server-7b8c9d Successfully pulled image registry.example.com/api:v2.1.0",
            "Event: deployment/worker-pool Scaled up replica set worker-pool-6a7b8c to 5",
            "Event: node/k8s-node03 NodeHasSufficientMemory status is now True",
            "trace_id=4bf92f3577b34da6 span_id=00f067aa0ba902b7 operation=db.query duration=4.2ms",
            "trace_id=a1b2c3d4e5f60718 span_id=1234567890abcdef operation=http.request duration=125ms",
            "trace_id=0123456789abcdef span_id=fedcba9876543210 operation=grpc.call duration=12ms",
            "trace_id=deadbeefcafebabe span_id=abcdef1234567890 operation=cache.get duration=0.3ms",
            "Event: ingress/main-ingress Updated load balancer with 3 endpoints",
            '10.0.1.102 - - [22/Mar/2024:14:08:02 +0000] "PUT /api/v3/config HTTP/2" 204 0',
            '10.0.1.103 - - [22/Mar/2024:14:08:03 +0000] "DELETE /api/v3/cache HTTP/2" 204 0',
            "2024-03-22 14:05:22.000 INFO [gc] Garbage collection completed: freed 256MB in 45ms",
            "2024-03-22 14:05:23.000 DEBUG [dns] Resolution for api.example.com: 1.2.3.4 (cached, ttl=300s)",
        ],
        "config": [
            "max_connections = 100",
            "idle_timeout_seconds = 300",
            "enable_compression = true",
            "log_format = json",
            "max_request_body_size = 10485760",
            "graceful_shutdown_timeout = 30",
            "health_check_interval = 10",
            "dns_cache_ttl = 600",
            "thread_pool_size = 16",
            "gc_interval_minutes = 15",
            'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app-config\ndata:\n  LOG_LEVEL: info\n  WORKER_COUNT: "8"',
            'resources:\n  requests:\n    cpu: 250m\n    memory: 512Mi\n  limits:\n    cpu: "1"\n    memory: 1Gi',
            "autoscaling:\n  enabled: true\n  minReplicas: 2\n  maxReplicas: 10\n  targetCPUUtilizationPercentage: 70",
            "prometheus:\n  serviceMonitor:\n    enabled: true\n    interval: 15s\n    path: /metrics",
            "livenessProbe:\n  httpGet:\n    path: /health/live\n    port: 8080\n  initialDelaySeconds: 15",
            '[build]\ntarget = "x86_64-unknown-linux-gnu"\nopt-level = 3',
            '[tool.ruff]\nline-length = 100\ntarget-version = "py312"',
            '[tool.pytest.ini_options]\naddopts = "-ra --strict-markers"\ntestpaths = ["tests"]',
            "[mysqld]\nmax_connections = 200\ninnodb_buffer_pool_size = 4G",
            "[sshd]\nPermitRootLogin = no\nMaxAuthTries = 3\nPasswordAuthentication = no",
            "NODE_ENV=production",
            "PORT=3000",
            "LOG_LEVEL=warn",
            "REDIS_HOST=redis.internal",
            "REDIS_PORT=6379",
            "DB_HOST=db.internal",
            "DB_PORT=5432",
            "DB_NAME=myapp_production",
            "CACHE_TTL=3600",
            "MAX_UPLOAD_SIZE=52428800",
            "CORS_ORIGINS=https://app.example.com,https://admin.example.com",
            "FEATURE_NEW_DASHBOARD=true",
            "SENTRY_ENVIRONMENT=production",
            "OTEL_EXPORTER_ENDPOINT=http://collector.internal:4317",
            "WORKERS=auto",
            "TZ=UTC",
            "services:\n  redis:\n    image: redis:7-alpine\n    ports:\n      - '6379:6379'\n    command: redis-server --maxmemory 256mb",
            "upstream backend {\n    least_conn;\n    server 10.0.1.10:8080 weight=3;\n    server 10.0.1.11:8080 backup;\n}",
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        python-version: ['3.11', '3.12', '3.13']",
            "ingress:\n  enabled: true\n  className: nginx\n  hosts:\n    - host: api.example.com",
            "[program:celery-worker]\ncommand = celery -A tasks worker --loglevel=info",
            '[dependencies]\ntokio = { version = "1.36", features = ["full"] }\nserde = { version = "1.0", features = ["derive"] }',
        ],
        "urls": [
            "https://console.cloud.google.com/kubernetes/clusters/details/us-central1-a/prod-cluster",
            "https://us-west-2.console.aws.amazon.com/ec2/v2/home?region=us-west-2",
            "https://portal.azure.com/#blade/HubsExtension/BrowseResource",
            "https://app.datadoghq.com/dashboard/abc-def-ghi/production-overview",
            "https://app.terraform.io/app/myorg/workspaces/production-infra",
            "https://circleci.com/gh/myorg/myrepo/tree/main",
            "https://linear.app/myorg/issue/ENG-5678/improve-query-performance",
            "https://vercel.com/myorg/frontend/deployments",
            "http://prometheus.monitoring.svc.cluster.local:9090/api/v1/query",
            "http://grafana.monitoring.svc.cluster.local:3000/d/k8s-overview",
            "http://jaeger.tracing.svc.cluster.local:16686/search?service=api-server",
            "http://argocd.gitops.svc.cluster.local:8080/applications/production-api",
            "http://vault.security.svc.cluster.local:8200/v1/sys/health",
            "https://hooks.example.com/webhooks/deploy/trigger",
            "https://api.example.com/callbacks/payment/completed",
            "https://api.example.com/v3/search?q=machine+learning&sort=relevance&limit=25",
            "https://api.example.com/v3/reports/export?format=csv&start=2024-01-01",
            "https://api.example.com/v3/users?role=admin&status=active&page=2",
            "https://api.example.com/v3/events?after=evt_abc123&limit=100",
            "https://api.example.com/v3/metrics?name=cpu_usage&resolution=1m",
            "https://crates.io/api/v1/crates/tokio/1.36.0/download",
            "https://registry.npmjs.org/@types/node/-/node-20.11.16.tgz",
            "https://repo1.maven.org/maven2/org/springframework/boot/3.2.2/",
            "https://pkg.go.dev/github.com/gorilla/mux@v1.8.1",
            "https://ghcr.io/v2/myorg/myapp/manifests/sha256:abcdef1234567890",
            "https://registry.hub.docker.com/v2/repositories/library/python/tags/3.12-slim",
            "https://api.example.com/v2/tokens/validate",
            "https://api.example.com/v2/credentials/rotate",
            "https://api.example.com/v2/secrets/list",
            "https://api.example.com/v2/keys/public",
            "https://api.example.com/v2/auth/callback",
            "https://api.example.com/v2/oauth/authorize?response_type=code",
            "https://status.example.com/api/v2/components.json",
            "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js",
            "s3://my-data-lake/raw/events/year=2024/month=03/part-00000.parquet",
            "gs://ml-training-data/datasets/v3/train.tfrecord",
            "https://myorg.atlassian.net/browse/PROJ-1234",
            "http://minio.storage.svc.cluster.local:9000/browser/data-lake/",
            "https://notify.example.com/events/build/status",
            "https://rubygems.org/api/v1/gems/rails/versions/7.1.3.json",
            "https://gcr.io/v2/my-project/api-server/blobs/sha256:0123456789abcdef",
            "wasb://container@storageaccount.blob.core.windows.net/data/export.csv",
            "https://app.launchdarkly.com/default/production/features/new-checkout-flow",
            "https://unpkg.com/htmx.org@1.9.10/dist/htmx.min.js",
            "http://kibana.logging.svc.cluster.local:5601/app/discover",
        ],
        "hashes": [
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "sha512:ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
            "sha512:b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
            "sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
            "sha1:7b502c3a1f48c8609ae212cdfb639dee39673f5e",
            "sha1:356a192b7913b04c54574d18c28d46e6395428ab",
            "md5:5d41402abc4b2a76b9719d911017c592",
            "md5:7d793037a0760186574b0282f2f435e7",
            "md5:e99a18c428cb38d5f260853678922e03",
            "uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "uuid:3d813cbb-47fb-32ba-91df-831e1593ac29",
            "uuid:c73bcdcc-2669-4bf6-81d3-e4ae73fb11fd",
            "uuid:9a3b4c5d-6e7f-8a9b-0c1d-2e3f4a5b6c7d",
            "trace-id:4bf92f3577b34da6a3ce929d0e0e4736",
            "trace-id:a1b2c3d4e5f60718a1b2c3d4e5f60718",
            "trace-id:0123456789abcdef0123456789abcdef",
            "span-id:00f067aa0ba902b7",
            "span-id:1234567890abcdef",
            "span-id:fedcba9876543210",
            "docker:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "docker:sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
            "tree:4b825dc642cb6eb9a060e54bf899d69f91a7e930",
            "blob:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            "crc32:3610a686",
            "crc32c:22620404",
            "adler32:11e60398",
            "xxhash64:d85cb510ae0b18d3",
            "fnv1a:811c9dc5",
            "cas:zQmPZ9gcCEpPKjMH8pCCSCYfHgmuVB4pYN1FJRaoE5Kzqj",
            "ipfs:QmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHE8P34isapyhCxX",
            "integrity:sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w",
            "integrity:sha256-BpfBw7ivV8q2jLiT13fxDYAe2tJllusRSZ273h2nFSE=",
            "request-id:5f3a8b2c1d4e6f0987654321",
            "session-id:a0b1c2d3e4f5a6b7c8d9e0f1",
            "correlation-id:1a2b3c4d5e6f7a8b9c0d1e2f",
            "sha256:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "tag:9da581d910c9c4ac93557ca4859e767f5caf5169",
            "md5:b1946ac92492d2347c6235b4d2611184",
            "sha3-256:a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            "xxhash:ef46db3751d8e999",
            "murmur3:76293a71",
            "ripemd160:9c1185a5c5e9fc54612808977ee8f548b2258d31",
            "blake2b:786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419",
        ],
        "edge_cases": [
            "AWS access keys always start with the prefix AKIA followed by 16 alphanumeric characters.",
            "GitHub tokens use prefixes like ghp_ for personal access tokens and gho_ for OAuth tokens.",
            "Stripe API keys follow the format sk_live_ or sk_test_ followed by at least 24 characters.",
            "The xoxb- prefix indicates a Slack bot token while xoxp- indicates a user token.",
            "To generate a new personal access token, navigate to Settings > Developer Settings > Tokens.",
            "Private keys are identified by the PEM header that begins with five dashes and the word BEGIN.",
            "JWTs consist of three base64url-encoded segments separated by dots, starting with eyJ.",
            "REPLACE_WITH_YOUR_ACTUAL_TOKEN_HERE",
            "INSERT_API_KEY_BEFORE_RUNNING",
            "YOUR_SECRET_GOES_HERE",
            "<YOUR_ACCESS_TOKEN>",
            "${GITHUB_TOKEN}",
            "$(AWS_ACCESS_KEY_ID)",
            "***REMOVED***",
            "REDACTED_FOR_SECURITY",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "0000000000000000000000000000000000000000",
            "DUMMY_VALUE_FOR_LOCAL_DEVELOPMENT_ONLY",
            "NOT_A_REAL_KEY_JUST_A_PLACEHOLDER_VALUE",
            "test_api_response_with_mock_credentials",
            "fixture_user_with_expired_session_token",
            "mock_oauth_callback_with_state_parameter",
            "fake_webhook_payload_for_integration_test",
            "expected_error_when_invalid_credentials_provided",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "STRIPE_SECRET_KEY",
            "DATABASE_URL",
            "OPENAI_API_KEY",
            "SLACK_BOT_TOKEN",
            "dGhpcyBpcyBqdXN0IGEgdGVzdA==",
            "aGVsbG8gd29ybGQ=",
            "VGhlIHF1aWNrIGJyb3du",
            "run_2c3d4e5f6a7b8c9d0e1f2a3b",
            "evt_9f8e7d6c5b4a3928f7e6d5c4",
            "txn_1a2b3c4d5e6f7890abcdef12",
            "inv_fedcba0987654321abcdef99",
            "sub_abc123def456ghi789jkl012",
            "cus_mno345pqr678stu901vwx234",
            "pi_1234567890abcdef12345678",
            "ghp_placeholder",
            "gho_not_real",
            "sk_live_short",
            "sk_test_nope",
            "AKIAEXAMP",
            "AKIA_NOT_A_KEY",
            "secret_rotation_interval_days: 90",
            "token_expiry_hours: 24",
            "credential_cache_ttl: 300",
            "api_key_rate_limit: 1000",
            "password_min_length: 12",
            "encryption_algorithm: AES-256-GCM",
            "hash_algorithm: bcrypt",
            "build-20240322-143052-a7b8c9d0",
            "release-v2.1.0-rc1-g4e5f6a7",
            "deploy-prod-us-east-1-20240322-001",
            "artifact-myapp-linux-amd64-v2.1.0",
            "scan-result-clean-no-findings-20240322",
            "pipeline-run-12345-stage-3-passed",
            "The OAuth 2.0 specification defines four grant types.",
            "stub_payment_processor_returns_success",
        ],
    }
