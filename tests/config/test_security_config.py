"""Tests for security configuration schema."""

import pytest
from pydantic import ValidationError

from harombe.config.schema import (
    AuditConfig,
    ContainerConfig,
    ContainerResourcesConfig,
    CredentialsConfig,
    GatewayConfig,
    HarombeConfig,
    HITLConfig,
    SecurityConfig,
)


def test_gateway_config_defaults():
    """Test GatewayConfig default values."""
    config = GatewayConfig()

    assert config.host == "127.0.0.1"
    assert config.port == 8100
    assert config.timeout == 30
    assert config.max_retries == 3


def test_gateway_config_custom():
    """Test GatewayConfig with custom values."""
    config = GatewayConfig(
        host="0.0.0.0",
        port=8200,
        timeout=60,
        max_retries=5,
    )

    assert config.host == "0.0.0.0"
    assert config.port == 8200
    assert config.timeout == 60
    assert config.max_retries == 5


def test_gateway_config_validation():
    """Test GatewayConfig validation."""
    # Invalid port
    with pytest.raises(ValidationError):
        GatewayConfig(port=70000)

    # Invalid timeout
    with pytest.raises(ValidationError):
        GatewayConfig(timeout=0)

    # Invalid retries
    with pytest.raises(ValidationError):
        GatewayConfig(max_retries=0)


def test_audit_config_defaults():
    """Test AuditConfig default values."""
    config = AuditConfig()

    assert config.enabled is True
    assert config.database == "~/.harombe/audit.db"
    assert config.retention_days == 90
    assert config.log_level == "INFO"


def test_audit_config_custom():
    """Test AuditConfig with custom values."""
    config = AuditConfig(
        enabled=False,
        database="/var/log/harombe/audit.db",
        retention_days=30,
        log_level="DEBUG",
    )

    assert config.enabled is False
    assert config.database == "/var/log/harombe/audit.db"
    assert config.retention_days == 30
    assert config.log_level == "DEBUG"


def test_credentials_config_defaults():
    """Test CredentialsConfig default values."""
    config = CredentialsConfig()

    assert config.method == "env"
    assert config.vault_addr is None
    assert config.vault_token == "~/.vault-token"
    assert config.auto_refresh is True
    assert config.rotation_days == 30


def test_credentials_config_vault():
    """Test CredentialsConfig with Vault."""
    config = CredentialsConfig(
        method="vault",
        vault_addr="http://localhost:8200",
        vault_token="/etc/vault-token",
        rotation_days=7,
    )

    assert config.method == "vault"
    assert config.vault_addr == "http://localhost:8200"
    assert config.vault_token == "/etc/vault-token"
    assert config.rotation_days == 7


def test_container_resources_defaults():
    """Test ContainerResourcesConfig defaults."""
    config = ContainerResourcesConfig()

    assert config.cpu_limit is None
    assert config.memory_limit is None
    assert config.pids_limit == 100


def test_container_resources_custom():
    """Test ContainerResourcesConfig with custom values."""
    config = ContainerResourcesConfig(
        cpu_limit="2",
        memory_limit="2g",
        pids_limit=50,
    )

    assert config.cpu_limit == "2"
    assert config.memory_limit == "2g"
    assert config.pids_limit == 50


def test_container_config_minimal():
    """Test ContainerConfig with minimal required fields."""
    config = ContainerConfig(image="harombe/browser:latest")

    assert config.image == "harombe/browser:latest"
    assert config.enabled is True
    assert config.resources.pids_limit == 100
    assert config.egress_allow == []
    assert config.mounts == []
    assert config.environment == {}
    assert config.timeout is None
    assert config.confirm_actions == []


def test_container_config_full():
    """Test ContainerConfig with all fields."""
    config = ContainerConfig(
        image="harombe/browser:latest",
        enabled=True,
        resources=ContainerResourcesConfig(
            cpu_limit="2",
            memory_limit="2g",
            pids_limit=50,
        ),
        egress_allow=["*.google.com", "*.github.com"],
        mounts=["/home/user/workspace:/workspace:rw"],
        environment={"LOG_LEVEL": "DEBUG"},
        timeout=60,
        confirm_actions=["send_email", "delete_*"],
    )

    assert config.image == "harombe/browser:latest"
    assert config.enabled is True
    assert config.resources.cpu_limit == "2"
    assert config.resources.memory_limit == "2g"
    assert len(config.egress_allow) == 2
    assert "*.google.com" in config.egress_allow
    assert len(config.mounts) == 1
    assert config.environment["LOG_LEVEL"] == "DEBUG"
    assert config.timeout == 60
    assert len(config.confirm_actions) == 2


def test_hitl_config_defaults():
    """Test HITLConfig default values."""
    config = HITLConfig()

    assert config.enabled is True
    assert config.timeout == 60
    assert config.notification_method == "cli"
    assert config.webhook_url is None


def test_hitl_config_webhook():
    """Test HITLConfig with webhook."""
    config = HITLConfig(
        enabled=True,
        timeout=30,
        notification_method="webhook",
        webhook_url="https://example.com/webhook",
    )

    assert config.notification_method == "webhook"
    assert config.webhook_url == "https://example.com/webhook"


def test_security_config_defaults():
    """Test SecurityConfig default values."""
    config = SecurityConfig()

    assert config.enabled is False
    assert config.isolation == "docker"
    assert config.gateway.host == "127.0.0.1"
    assert config.gateway.port == 8100
    assert config.audit.enabled is True
    assert config.credentials.method == "env"
    assert config.containers == {}
    assert config.hitl.enabled is True


def test_security_config_enabled():
    """Test SecurityConfig when enabled."""
    config = SecurityConfig(
        enabled=True,
        isolation="gvisor",
        gateway=GatewayConfig(port=8200),
        containers={
            "browser": ContainerConfig(
                image="harombe/browser:latest",
                resources=ContainerResourcesConfig(
                    cpu_limit="2",
                    memory_limit="2g",
                ),
            ),
            "filesystem": ContainerConfig(
                image="harombe/filesystem:latest",
                resources=ContainerResourcesConfig(
                    cpu_limit="1",
                    memory_limit="512m",
                ),
            ),
        },
    )

    assert config.enabled is True
    assert config.isolation == "gvisor"
    assert config.gateway.port == 8200
    assert len(config.containers) == 2
    assert "browser" in config.containers
    assert "filesystem" in config.containers
    assert config.containers["browser"].resources.cpu_limit == "2"
    assert config.containers["filesystem"].resources.memory_limit == "512m"


def test_security_config_in_harombe_config():
    """Test SecurityConfig as part of HarombeConfig."""
    config = HarombeConfig(
        security=SecurityConfig(
            enabled=True,
            containers={
                "browser": ContainerConfig(image="harombe/browser:latest"),
            },
        ),
    )

    assert config.security.enabled is True
    assert "browser" in config.security.containers


def test_harombe_config_default_security():
    """Test HarombeConfig has disabled security by default."""
    config = HarombeConfig()

    assert config.security.enabled is False
    assert config.security.containers == {}


def test_security_config_yaml_roundtrip():
    """Test security config can be serialized to/from dict (YAML-like)."""
    config = SecurityConfig(
        enabled=True,
        isolation="docker",
        gateway=GatewayConfig(
            host="0.0.0.0",
            port=8100,
        ),
        containers={
            "browser": ContainerConfig(
                image="harombe/browser:latest",
                resources=ContainerResourcesConfig(
                    cpu_limit="2",
                    memory_limit="2g",
                ),
                egress_allow=["*.google.com"],
            ),
        },
    )

    # Serialize to dict
    config_dict = config.model_dump()

    assert config_dict["enabled"] is True
    assert config_dict["isolation"] == "docker"
    assert config_dict["gateway"]["host"] == "0.0.0.0"
    assert "browser" in config_dict["containers"]

    # Deserialize from dict
    config_restored = SecurityConfig(**config_dict)

    assert config_restored.enabled is True
    assert config_restored.isolation == "docker"
    assert config_restored.gateway.host == "0.0.0.0"
    assert "browser" in config_restored.containers
    assert config_restored.containers["browser"].resources.cpu_limit == "2"


def test_container_config_validation():
    """Test ContainerConfig validation."""
    # Valid timeout
    config = ContainerConfig(image="test:latest", timeout=30)
    assert config.timeout == 30

    # Invalid timeout (must be >= 1)
    with pytest.raises(ValidationError):
        ContainerConfig(image="test:latest", timeout=0)


def test_credentials_config_validation():
    """Test CredentialsConfig validation."""
    # Valid method
    config = CredentialsConfig(method="vault")
    assert config.method == "vault"

    # Invalid method
    with pytest.raises(ValidationError):
        CredentialsConfig(method="invalid")

    # Valid rotation days
    config = CredentialsConfig(rotation_days=7)
    assert config.rotation_days == 7

    # Invalid rotation days
    with pytest.raises(ValidationError):
        CredentialsConfig(rotation_days=0)


def test_hitl_config_validation():
    """Test HITLConfig validation."""
    # Valid notification method
    config = HITLConfig(notification_method="webhook")
    assert config.notification_method == "webhook"

    # Invalid notification method
    with pytest.raises(ValidationError):
        HITLConfig(notification_method="invalid")

    # Valid timeout
    config = HITLConfig(timeout=120)
    assert config.timeout == 120

    # Invalid timeout
    with pytest.raises(ValidationError):
        HITLConfig(timeout=0)


def test_security_config_isolation_validation():
    """Test SecurityConfig isolation validation."""
    # Valid isolation
    config = SecurityConfig(isolation="gvisor")
    assert config.isolation == "gvisor"

    # Invalid isolation
    with pytest.raises(ValidationError):
        SecurityConfig(isolation="invalid")


def test_audit_config_validation():
    """Test AuditConfig validation."""
    # Valid log level
    config = AuditConfig(log_level="DEBUG")
    assert config.log_level == "DEBUG"

    # Invalid log level
    with pytest.raises(ValidationError):
        AuditConfig(log_level="INVALID")

    # Valid retention days
    config = AuditConfig(retention_days=30)
    assert config.retention_days == 30

    # Invalid retention days
    with pytest.raises(ValidationError):
        AuditConfig(retention_days=0)
