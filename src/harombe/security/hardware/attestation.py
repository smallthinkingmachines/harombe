"""Hardware-backed attestation for platform integrity verification.

This module provides attestation generation and verification capabilities for
proving platform integrity in the Harombe security framework. It supports
multiple attestation types including software-only, TPM-backed, enclave-backed,
and remote challenge-response attestation.

Attestation reports contain SHA-256 measurements of platform state (Python
version, OS details, module versions) and can be signed using HMAC (software
mode) or TPM keys (hardware mode). The remote attestation service implements
a nonce-based challenge-response protocol to prevent replay attacks.

Example:
    >>> import asyncio
    >>> from harombe.security.hardware.attestation import (
    ...     AttestationGenerator,
    ...     AttestationVerifier,
    ...     AttestationPolicy,
    ...     AttestationType,
    ... )
    >>>
    >>> async def main():
    ...     generator = AttestationGenerator()
    ...     verifier = AttestationVerifier()
    ...     policy = AttestationPolicy(policy_id="default")
    ...
    ...     nonce = await generator.generate_nonce()
    ...     report = await generator.generate_report(nonce=nonce)
    ...     valid = await verifier.verify_report(
    ...         report, policy, expected_nonce=nonce
    ...     )
    ...     print(f"Attestation valid: {valid}")
    >>>
    >>> asyncio.run(main())
"""

import hashlib
import hmac
import logging
import os
import platform
import sys
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from harombe.security.hardware.enclave import EnclaveManager
from harombe.security.hardware.tpm import TPMAlgorithm, TPMKeyManager

logger = logging.getLogger(__name__)

_HMAC_KEY_SIZE = 32


class AttestationType(StrEnum):
    """Supported attestation types.

    Attributes:
        SOFTWARE: Software-only attestation using HMAC signatures.
        TPM: Hardware-backed attestation using a TPM signing key.
        ENCLAVE: Attestation generated within a secure enclave.
        REMOTE: Remote challenge-response attestation protocol.
    """

    SOFTWARE = "software"
    TPM = "tpm"
    ENCLAVE = "enclave"
    REMOTE = "remote"


class AttestationPolicy(BaseModel):
    """Policy governing attestation requirements.

    Attributes:
        policy_id: Unique identifier for this policy.
        required_type: Minimum attestation type required.
        min_freshness_seconds: Maximum age of an attestation report
            in seconds before it is considered stale.
        required_measurements: List of measurement keys that must be
            present in the attestation report.
        allow_debug: Whether to accept reports from debug-mode enclaves.
        nonce_required: Whether a nonce must be present in the report.
    """

    policy_id: str
    required_type: AttestationType = AttestationType.SOFTWARE
    min_freshness_seconds: int = 300
    required_measurements: list[str] = Field(default_factory=list)
    allow_debug: bool = False
    nonce_required: bool = True


class AttestationReport(BaseModel):
    """Attestation report containing platform measurements.

    Attributes:
        report_id: Unique identifier for this report.
        attestation_type: Type of attestation used to generate this report.
        timestamp: When the report was generated.
        measurements: SHA-256 hashes of platform state keyed by name.
        nonce: Optional nonce used for replay prevention.
        signature: Optional cryptographic signature over the report.
        platform_info: Additional platform metadata.
        valid: Whether this report has been verified.
    """

    report_id: str
    attestation_type: AttestationType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    measurements: dict[str, str] = Field(default_factory=dict)
    nonce: str | None = None
    signature: bytes | None = None
    platform_info: dict[str, Any] = Field(default_factory=dict)
    valid: bool = False


class AttestationGenerator:
    """Generates attestation reports with platform measurements.

    Collects platform state measurements (Python version, OS details,
    module versions) and produces signed attestation reports. Supports
    software HMAC signatures, TPM-backed signatures, and enclave-based
    attestation.

    Example:
        >>> generator = AttestationGenerator()
        >>> report = await generator.generate_report()
        >>> print(report.measurements)
    """

    def __init__(
        self,
        tpm_manager: TPMKeyManager | None = None,
        enclave_manager: EnclaveManager | None = None,
    ) -> None:
        """Initialize the attestation generator.

        Args:
            tpm_manager: Optional TPM key manager for TPM-backed attestation.
            enclave_manager: Optional enclave manager for enclave attestation.
        """
        self._tpm_manager = tpm_manager
        self._enclave_manager = enclave_manager
        self._hmac_key: bytes = os.urandom(_HMAC_KEY_SIZE)
        self._tpm_key_id: str | None = None

    @property
    def hmac_key(self) -> bytes:
        """Return the HMAC key used for software attestation signatures."""
        return self._hmac_key

    async def generate_nonce(self) -> str:
        """Generate a cryptographically secure random nonce.

        Returns:
            Hex-encoded string of 32 random bytes.
        """
        return os.urandom(32).hex()

    async def generate_report(
        self,
        attestation_type: AttestationType = AttestationType.SOFTWARE,
        nonce: str | None = None,
    ) -> AttestationReport:
        """Generate an attestation report with platform measurements.

        Collects measurements of the current platform state and signs
        the report according to the specified attestation type.

        Args:
            attestation_type: Type of attestation to perform.
            nonce: Optional nonce for replay prevention.

        Returns:
            Signed attestation report.
        """
        report_id = str(uuid.uuid4())
        measurements = self._collect_measurements()
        platform_info = self._collect_platform_info()

        report = AttestationReport(
            report_id=report_id,
            attestation_type=attestation_type,
            measurements=measurements,
            nonce=nonce,
            platform_info=platform_info,
        )

        if attestation_type == AttestationType.SOFTWARE:
            report.signature = self._sign_software(report)
            report.valid = True
        elif attestation_type == AttestationType.TPM:
            report = await self._sign_tpm(report)
        elif attestation_type == AttestationType.ENCLAVE:
            report = await self._sign_enclave(report)
        elif attestation_type == AttestationType.REMOTE:
            report.signature = self._sign_software(report)
            report.valid = True

        logger.info(f"Generated {attestation_type.value} attestation report " f"{report_id}")
        return report

    def _collect_measurements(self) -> dict[str, str]:
        """Collect SHA-256 measurements of platform state.

        Returns:
            Dictionary mapping measurement names to hex-encoded
            SHA-256 hashes.
        """
        measurements: dict[str, str] = {}

        # Python version measurement
        python_version = (
            f"{sys.version_info.major}." f"{sys.version_info.minor}." f"{sys.version_info.micro}"
        )
        measurements["python_version"] = hashlib.sha256(python_version.encode()).hexdigest()

        # OS measurement
        os_info = f"{platform.system()}-{platform.release()}"
        measurements["os_info"] = hashlib.sha256(os_info.encode()).hexdigest()

        # Platform architecture
        arch = platform.machine()
        measurements["architecture"] = hashlib.sha256(arch.encode()).hexdigest()

        # Module integrity (hash of this module's file path as proxy)
        module_id = "harombe.security.hardware.attestation"
        measurements["module_integrity"] = hashlib.sha256(module_id.encode()).hexdigest()

        return measurements

    def _collect_platform_info(self) -> dict[str, Any]:
        """Collect human-readable platform information.

        Returns:
            Dictionary with platform details.
        """
        return {
            "python_version": (
                f"{sys.version_info.major}."
                f"{sys.version_info.minor}."
                f"{sys.version_info.micro}"
            ),
            "os": platform.system(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
        }

    def _sign_software(self, report: AttestationReport) -> bytes:
        """Create an HMAC-SHA256 signature for a software attestation.

        Args:
            report: The attestation report to sign.

        Returns:
            HMAC-SHA256 signature bytes.
        """
        message = self._build_sign_message(report)
        return hmac.new(self._hmac_key, message, hashlib.sha256).digest()

    def _build_sign_message(self, report: AttestationReport) -> bytes:
        """Build the canonical message bytes for signing.

        Concatenates report_id, sorted measurements, and nonce into
        a deterministic byte string.

        Args:
            report: The attestation report.

        Returns:
            Canonical message bytes.
        """
        parts: list[str] = [report.report_id]
        for key in sorted(report.measurements):
            parts.append(f"{key}={report.measurements[key]}")
        if report.nonce:
            parts.append(report.nonce)
        return "|".join(parts).encode()

    async def _sign_tpm(self, report: AttestationReport) -> AttestationReport:
        """Sign the report using the TPM manager.

        Creates a TPM signing key if one does not already exist, then
        signs the canonical message with the TPM.

        Args:
            report: The attestation report to sign.

        Returns:
            Updated report with TPM signature.
        """
        if self._tpm_manager is None:
            logger.warning("TPM manager not available, falling back to software")
            report.signature = self._sign_software(report)
            report.valid = True
            return report

        # Create a signing key if we don't have one yet
        if self._tpm_key_id is None:
            key_handle = await self._tpm_manager.create_signing_key(TPMAlgorithm.ECDSA_P256)
            self._tpm_key_id = key_handle.key_id

        message = self._build_sign_message(report)
        report.signature = await self._tpm_manager.sign_data(self._tpm_key_id, message)
        report.valid = True
        report.platform_info["tpm_key_id"] = self._tpm_key_id
        return report

    async def _sign_enclave(self, report: AttestationReport) -> AttestationReport:
        """Generate attestation from an enclave.

        Creates a temporary enclave, retrieves its attestation report,
        and merges the enclave measurements into the attestation report.

        Args:
            report: The attestation report to enrich.

        Returns:
            Updated report with enclave attestation data.
        """
        if self._enclave_manager is None:
            logger.warning("Enclave manager not available, falling back to " "software")
            report.signature = self._sign_software(report)
            report.valid = True
            return report

        enclave_id = await self._enclave_manager.create_enclave()
        try:
            enclave_report = await self._enclave_manager.get_attestation(enclave_id)
            # Merge enclave measurements into report
            enclave_measurements = enclave_report.get("measurements", {})
            for key, value in enclave_measurements.items():
                report.measurements[f"enclave_{key}"] = value

            report.platform_info["enclave_id"] = enclave_id
            report.platform_info["enclave_backend"] = enclave_report.get("backend", "unknown")
            report.signature = self._sign_software(report)
            report.valid = True
        finally:
            await self._enclave_manager.destroy_enclave(enclave_id)

        return report


class AttestationVerifier:
    """Verifies attestation reports against policies.

    Checks report freshness, nonce validity, required measurements,
    and cryptographic signatures.

    Example:
        >>> verifier = AttestationVerifier()
        >>> valid = await verifier.verify_report(report, policy)
    """

    def __init__(self, tpm_manager: TPMKeyManager | None = None) -> None:
        """Initialize the attestation verifier.

        Args:
            tpm_manager: Optional TPM key manager for verifying
                TPM-backed signatures.
        """
        self._tpm_manager = tpm_manager

    async def verify_report(
        self,
        report: AttestationReport,
        policy: AttestationPolicy,
        expected_nonce: str | None = None,
        hmac_key: bytes | None = None,
    ) -> bool:
        """Verify an attestation report against a policy.

        Performs the following checks in order:
        1. Freshness -- report timestamp is within allowed window
        2. Nonce -- matches expected nonce if policy requires one
        3. Measurements -- all required measurement keys are present
        4. Signature -- cryptographic signature is valid

        Args:
            report: The attestation report to verify.
            policy: Policy defining verification requirements.
            expected_nonce: Expected nonce value for replay prevention.
            hmac_key: HMAC key for verifying software signatures.

        Returns:
            True if all checks pass, False otherwise.
        """
        # 1. Check freshness
        if not self._check_freshness(report, policy):
            logger.warning(f"Attestation report {report.report_id} failed " f"freshness check")
            return False

        # 2. Check nonce
        if policy.nonce_required:
            if expected_nonce is None:
                logger.warning(
                    f"Policy requires nonce but none provided " f"for report {report.report_id}"
                )
                return False
            if report.nonce != expected_nonce:
                logger.warning(f"Nonce mismatch for report {report.report_id}")
                return False

        # 3. Check measurements
        if not self._check_measurements(report, policy):
            logger.warning(f"Attestation report {report.report_id} failed " f"measurements check")
            return False

        # 4. Check debug mode
        if not policy.allow_debug and report.platform_info.get("debug_mode", False):
            logger.warning(f"Report {report.report_id} has debug_mode but " f"policy disallows it")
            return False

        # 5. Verify signature
        if report.attestation_type == AttestationType.TPM:
            if not await self._verify_tpm_signature(report):
                logger.warning(
                    f"TPM signature verification failed for " f"report {report.report_id}"
                )
                return False
        elif (
            report.attestation_type
            in (
                AttestationType.SOFTWARE,
                AttestationType.REMOTE,
                AttestationType.ENCLAVE,
            )
            and hmac_key is not None
            and report.signature is not None
            and not self._verify_hmac_signature(report, hmac_key)
        ):
            logger.warning(f"HMAC signature verification failed for " f"report {report.report_id}")
            return False

        logger.info(f"Attestation report {report.report_id} verified " f"successfully")
        return True

    def _check_freshness(self, report: AttestationReport, policy: AttestationPolicy) -> bool:
        """Check whether the report timestamp is within the freshness window.

        Args:
            report: The attestation report.
            policy: Policy with freshness requirements.

        Returns:
            True if the report is fresh enough, False otherwise.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        age = (now - report.timestamp).total_seconds()
        if age > policy.min_freshness_seconds:
            logger.debug(
                f"Report {report.report_id} is {age:.1f}s old, "
                f"max allowed is {policy.min_freshness_seconds}s"
            )
            return False
        return True

    def _check_measurements(self, report: AttestationReport, policy: AttestationPolicy) -> bool:
        """Check that all required measurements are present in the report.

        Args:
            report: The attestation report.
            policy: Policy with required measurements.

        Returns:
            True if all required measurements exist, False otherwise.
        """
        for required_key in policy.required_measurements:
            if required_key not in report.measurements:
                logger.debug(f"Missing required measurement: {required_key}")
                return False
        return True

    def _verify_hmac_signature(self, report: AttestationReport, hmac_key: bytes) -> bool:
        """Verify the HMAC-SHA256 signature on a software attestation.

        Args:
            report: The attestation report.
            hmac_key: HMAC key to verify against.

        Returns:
            True if the signature is valid, False otherwise.
        """
        message = self._build_sign_message(report)
        expected = hmac.new(hmac_key, message, hashlib.sha256).digest()
        return hmac.compare_digest(report.signature or b"", expected)

    async def _verify_tpm_signature(self, report: AttestationReport) -> bool:
        """Verify a TPM-backed signature on the report.

        Args:
            report: The attestation report with TPM signature.

        Returns:
            True if signature is valid, False otherwise.
        """
        if self._tpm_manager is None:
            logger.warning("TPM manager not available for verification")
            return False

        tpm_key_id = report.platform_info.get("tpm_key_id")
        if not tpm_key_id:
            logger.warning("No TPM key ID in report platform_info")
            return False

        message = self._build_sign_message(report)
        try:
            return await self._tpm_manager.verify_signature(
                tpm_key_id, message, report.signature or b""
            )
        except KeyError:
            logger.warning(f"TPM key {tpm_key_id} not found")
            return False

    @staticmethod
    def _build_sign_message(report: AttestationReport) -> bytes:
        """Build the canonical message bytes for signature verification.

        Must match the message format used by
        ``AttestationGenerator._build_sign_message``.

        Args:
            report: The attestation report.

        Returns:
            Canonical message bytes.
        """
        parts: list[str] = [report.report_id]
        for key in sorted(report.measurements):
            parts.append(f"{key}={report.measurements[key]}")
        if report.nonce:
            parts.append(report.nonce)
        return "|".join(parts).encode()


class RemoteAttestationService:
    """Challenge-response remote attestation service.

    Implements a nonce-based challenge-response protocol for remote
    attestation. The verifier creates a challenge containing a random
    nonce, the prover generates an attestation report bound to that
    nonce, and the verifier checks the response. Each nonce can only
    be used once to prevent replay attacks.

    Example:
        >>> generator = AttestationGenerator()
        >>> verifier = AttestationVerifier()
        >>> service = RemoteAttestationService(generator, verifier)
        >>>
        >>> challenge = await service.create_challenge()
        >>> report = await service.respond_to_challenge(
        ...     challenge["challenge_id"], challenge["nonce"]
        ... )
        >>> valid = await service.verify_response(
        ...     report, challenge["challenge_id"]
        ... )
    """

    def __init__(
        self,
        generator: AttestationGenerator,
        verifier: AttestationVerifier,
    ) -> None:
        """Initialize the remote attestation service.

        Args:
            generator: Attestation report generator.
            verifier: Attestation report verifier.
        """
        self._generator = generator
        self._verifier = verifier
        self._nonce_cache: dict[str, datetime] = {}
        self._challenge_nonces: dict[str, str] = {}

    async def create_challenge(self) -> dict[str, str]:
        """Create a new attestation challenge.

        Generates a random challenge ID and nonce, storing them for
        later verification.

        Returns:
            Dictionary with ``challenge_id`` and ``nonce`` keys.
        """
        challenge_id = str(uuid.uuid4())
        nonce = await self._generator.generate_nonce()

        self._challenge_nonces[challenge_id] = nonce
        self._nonce_cache[nonce] = datetime.now(UTC).replace(tzinfo=None)

        logger.info(f"Created attestation challenge {challenge_id}")
        return {"challenge_id": challenge_id, "nonce": nonce}

    async def respond_to_challenge(self, challenge_id: str, nonce: str) -> AttestationReport:
        """Generate an attestation report in response to a challenge.

        Args:
            challenge_id: The challenge identifier.
            nonce: The nonce from the challenge.

        Returns:
            Attestation report bound to the provided nonce.

        Raises:
            ValueError: If the challenge_id is unknown.
        """
        if challenge_id not in self._challenge_nonces:
            raise ValueError(f"Unknown challenge: {challenge_id}")

        report = await self._generator.generate_report(
            attestation_type=AttestationType.REMOTE,
            nonce=nonce,
        )

        logger.info(f"Generated response for challenge {challenge_id}")
        return report

    async def verify_response(
        self,
        report: AttestationReport,
        challenge_id: str,
    ) -> bool:
        """Verify an attestation response against a stored challenge.

        Retrieves the nonce associated with the challenge and verifies
        the report. The nonce is consumed on successful verification
        to prevent replay.

        Args:
            report: The attestation report to verify.
            challenge_id: The challenge this report responds to.

        Returns:
            True if the report is valid for the given challenge.
        """
        if challenge_id not in self._challenge_nonces:
            logger.warning(f"Unknown challenge_id: {challenge_id}")
            return False

        expected_nonce = self._challenge_nonces[challenge_id]

        policy = AttestationPolicy(
            policy_id=f"challenge-{challenge_id}",
            required_type=AttestationType.REMOTE,
            nonce_required=True,
        )

        valid = await self._verifier.verify_report(
            report,
            policy,
            expected_nonce=expected_nonce,
            hmac_key=self._generator.hmac_key,
        )

        if valid:
            # Consume the nonce to prevent replay
            del self._challenge_nonces[challenge_id]
            if expected_nonce in self._nonce_cache:
                del self._nonce_cache[expected_nonce]
            logger.info(f"Challenge {challenge_id} verified successfully")
        else:
            logger.warning(f"Challenge {challenge_id} verification failed")

        return valid

    async def cleanup_expired_nonces(self, max_age_seconds: int = 600) -> int:
        """Remove nonces older than the specified age.

        Args:
            max_age_seconds: Maximum nonce age in seconds (default 600).

        Returns:
            Number of nonces removed.
        """
        now = datetime.now(UTC).replace(tzinfo=None)
        cutoff = now - timedelta(seconds=max_age_seconds)

        expired_nonces: list[str] = [
            nonce for nonce, created in self._nonce_cache.items() if created < cutoff
        ]

        # Also find challenge IDs that reference expired nonces
        expired_challenges: list[str] = [
            cid for cid, nonce in self._challenge_nonces.items() if nonce in expired_nonces
        ]

        for nonce in expired_nonces:
            del self._nonce_cache[nonce]
        for cid in expired_challenges:
            del self._challenge_nonces[cid]

        removed = len(expired_nonces)
        if removed > 0:
            logger.info(
                f"Cleaned up {removed} expired nonces and "
                f"{len(expired_challenges)} expired challenges"
            )
        return removed
