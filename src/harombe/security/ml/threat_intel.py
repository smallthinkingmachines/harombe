"""Threat intelligence integration for external threat feeds."""

import asyncio
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class ThreatCache:
    """Cache for threat intelligence lookups."""

    def __init__(self, ttl: int = 3600):
        """Initialize threat cache.

        Args:
            ttl: Time to live in seconds (default: 1 hour)
        """
        self.ttl = ttl
        self.cache: dict[str, tuple[float, float]] = {}  # key -> (score, timestamp)

    def get(self, key: str) -> float | None:
        """Get cached threat score.

        Args:
            key: Cache key

        Returns:
            Cached score or None if not found/expired
        """
        if key in self.cache:
            score, timestamp = self.cache[key]
            if time.time() - timestamp < self.ttl:
                return score
            else:
                # Expired, remove from cache
                del self.cache[key]
        return None

    def set(self, key: str, score: float) -> None:
        """Cache a threat score.

        Args:
            key: Cache key
            score: Threat score to cache
        """
        self.cache[key] = (score, time.time())

    def clear(self) -> None:
        """Clear all cached entries."""
        self.cache.clear()

    def cleanup_expired(self) -> None:
        """Remove expired entries from cache."""
        current_time = time.time()
        expired_keys = [
            key
            for key, (_, timestamp) in self.cache.items()
            if current_time - timestamp >= self.ttl
        ]
        for key in expired_keys:
            del self.cache[key]


class ThreatFeed:
    """Base class for threat intelligence feeds."""

    def __init__(self, name: str, base_url: str, api_key: str | None = None):
        """Initialize threat feed.

        Args:
            name: Feed name
            base_url: Base URL for API
            api_key: Optional API key
        """
        self.name = name
        self.base_url = base_url
        self.api_key = api_key
        self.client = httpx.AsyncClient(timeout=10.0)

        # Rate limiting
        self.last_request_time = 0.0
        self.min_request_interval = 1.0  # 1 second between requests

    async def _rate_limit(self) -> None:
        """Apply rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_request_interval:
            await asyncio.sleep(self.min_request_interval - time_since_last)
        self.last_request_time = time.time()

    async def lookup_ip(self, ip: str) -> float:
        """Lookup IP reputation.

        Args:
            ip: IP address

        Returns:
            Threat score (0-1)
        """
        raise NotImplementedError

    async def lookup_domain(self, domain: str) -> float:
        """Lookup domain reputation.

        Args:
            domain: Domain name

        Returns:
            Threat score (0-1)
        """
        raise NotImplementedError

    async def lookup_hash(self, file_hash: str) -> float:
        """Lookup file hash.

        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)

        Returns:
            Threat score (0-1)
        """
        raise NotImplementedError

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.aclose()


class AbuseIPDBFeed(ThreatFeed):
    """AbuseIPDB threat intelligence feed."""

    def __init__(self, api_key: str):
        """Initialize AbuseIPDB feed.

        Args:
            api_key: AbuseIPDB API key
        """
        super().__init__("AbuseIPDB", "https://api.abuseipdb.com/api/v2", api_key)

    async def lookup_ip(self, ip: str) -> float:
        """Lookup IP in AbuseIPDB.

        Args:
            ip: IP address

        Returns:
            Threat score (0-1)
        """
        if not self.api_key:
            return 0.0

        try:
            await self._rate_limit()

            response = await self.client.get(
                f"{self.base_url}/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
            )

            if response.status_code == 200:
                data = response.json()
                # AbuseIPDB returns abuse confidence (0-100)
                abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
                return float(min(abuse_score / 100.0, 1.0))
            else:
                logger.warning(f"AbuseIPDB lookup failed: {response.status_code} - {response.text}")
                return 0.0

        except Exception as e:
            logger.error(f"AbuseIPDB lookup error: {e}")
            return 0.0

    async def lookup_domain(self, domain: str) -> float:
        """AbuseIPDB doesn't support domain lookups."""
        return 0.0

    async def lookup_hash(self, file_hash: str) -> float:
        """AbuseIPDB doesn't support hash lookups."""
        return 0.0


class VirusTotalFeed(ThreatFeed):
    """VirusTotal threat intelligence feed."""

    def __init__(self, api_key: str):
        """Initialize VirusTotal feed.

        Args:
            api_key: VirusTotal API key
        """
        super().__init__("VirusTotal", "https://www.virustotal.com/api/v3", api_key)
        self.min_request_interval = 15.0  # Free tier: 4 requests/minute

    async def lookup_ip(self, ip: str) -> float:
        """Lookup IP in VirusTotal.

        Args:
            ip: IP address

        Returns:
            Threat score (0-1)
        """
        if not self.api_key:
            return 0.0

        try:
            await self._rate_limit()

            response = await self.client.get(
                f"{self.base_url}/ip_addresses/{ip}",
                headers={"x-apikey": self.api_key},
            )

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())

                if total > 0:
                    return float(min(malicious / total, 1.0))
                return 0.0
            else:
                logger.warning(f"VirusTotal IP lookup failed: {response.status_code}")
                return 0.0

        except Exception as e:
            logger.error(f"VirusTotal IP lookup error: {e}")
            return 0.0

    async def lookup_domain(self, domain: str) -> float:
        """Lookup domain in VirusTotal.

        Args:
            domain: Domain name

        Returns:
            Threat score (0-1)
        """
        if not self.api_key:
            return 0.0

        try:
            await self._rate_limit()

            response = await self.client.get(
                f"{self.base_url}/domains/{domain}",
                headers={"x-apikey": self.api_key},
            )

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())

                if total > 0:
                    return float(min((malicious + suspicious * 0.5) / total, 1.0))
                return 0.0
            else:
                logger.warning(f"VirusTotal domain lookup failed: {response.status_code}")
                return 0.0

        except Exception as e:
            logger.error(f"VirusTotal domain lookup error: {e}")
            return 0.0

    async def lookup_hash(self, file_hash: str) -> float:
        """Lookup file hash in VirusTotal.

        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)

        Returns:
            Threat score (0-1)
        """
        if not self.api_key:
            return 0.0

        try:
            await self._rate_limit()

            response = await self.client.get(
                f"{self.base_url}/files/{file_hash}",
                headers={"x-apikey": self.api_key},
            )

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())

                if total > 0:
                    return float(min(malicious / total, 1.0))
                return 0.0
            else:
                logger.warning(f"VirusTotal hash lookup failed: {response.status_code}")
                return 0.0

        except Exception as e:
            logger.error(f"VirusTotal hash lookup error: {e}")
            return 0.0


class AlienVaultOTXFeed(ThreatFeed):
    """AlienVault OTX threat intelligence feed."""

    def __init__(self, api_key: str):
        """Initialize AlienVault OTX feed.

        Args:
            api_key: OTX API key
        """
        super().__init__("AlienVault OTX", "https://otx.alienvault.com/api/v1", api_key)

    async def lookup_ip(self, ip: str) -> float:
        """Lookup IP in AlienVault OTX.

        Args:
            ip: IP address

        Returns:
            Threat score (0-1)
        """
        if not self.api_key:
            return 0.0

        try:
            await self._rate_limit()

            response = await self.client.get(
                f"{self.base_url}/indicators/IPv4/{ip}/reputation",
                headers={"X-OTX-API-KEY": self.api_key},
            )

            if response.status_code == 200:
                data = response.json()
                # OTX returns threat score and activity counts
                reputation = data.get("reputation", {})
                threat_score = reputation.get("threat_score", 0)

                # Normalize to 0-1 (OTX scores are typically 0-7)
                return float(min(threat_score / 7.0, 1.0))
            else:
                logger.warning(f"AlienVault OTX IP lookup failed: {response.status_code}")
                return 0.0

        except Exception as e:
            logger.error(f"AlienVault OTX IP lookup error: {e}")
            return 0.0

    async def lookup_domain(self, domain: str) -> float:
        """Lookup domain in AlienVault OTX.

        Args:
            domain: Domain name

        Returns:
            Threat score (0-1)
        """
        if not self.api_key:
            return 0.0

        try:
            await self._rate_limit()

            response = await self.client.get(
                f"{self.base_url}/indicators/domain/{domain}/reputation",
                headers={"X-OTX-API-KEY": self.api_key},
            )

            if response.status_code == 200:
                data = response.json()
                reputation = data.get("reputation", {})
                threat_score = reputation.get("threat_score", 0)

                return float(min(threat_score / 7.0, 1.0))
            else:
                logger.warning(f"AlienVault OTX domain lookup failed: {response.status_code}")
                return 0.0

        except Exception as e:
            logger.error(f"AlienVault OTX domain lookup error: {e}")
            return 0.0

    async def lookup_hash(self, file_hash: str) -> float:
        """Lookup file hash in AlienVault OTX.

        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)

        Returns:
            Threat score (0-1)
        """
        if not self.api_key:
            return 0.0

        try:
            await self._rate_limit()

            # Determine hash type
            hash_type = "file"
            if len(file_hash) == 32:
                hash_type = "file"  # MD5
            elif len(file_hash) == 40:
                hash_type = "file"  # SHA1
            elif len(file_hash) == 64:
                hash_type = "file"  # SHA256

            response = await self.client.get(
                f"{self.base_url}/indicators/{hash_type}/{file_hash}/analysis",
                headers={"X-OTX-API-KEY": self.api_key},
            )

            if response.status_code == 200:
                data = response.json()
                # Check if file is flagged as malicious
                analysis = data.get("analysis", {})
                malware = analysis.get("malware", {})

                if malware:
                    return 1.0  # Confirmed malware
                return 0.0
            else:
                logger.warning(f"AlienVault OTX hash lookup failed: {response.status_code}")
                return 0.0

        except Exception as e:
            logger.error(f"AlienVault OTX hash lookup error: {e}")
            return 0.0


class ThreatIntelligence:
    """External threat intelligence integration.

    Aggregates threat intelligence from multiple feeds with caching
    and rate limiting.
    """

    def __init__(
        self,
        abuseipdb_key: str | None = None,
        virustotal_key: str | None = None,
        alienvault_key: str | None = None,
        cache_ttl: int = 3600,
    ):
        """Initialize threat intelligence.

        Args:
            abuseipdb_key: AbuseIPDB API key
            virustotal_key: VirusTotal API key
            alienvault_key: AlienVault OTX API key
            cache_ttl: Cache TTL in seconds (default: 1 hour)
        """
        self.feeds: list[ThreatFeed] = []

        if abuseipdb_key:
            self.feeds.append(AbuseIPDBFeed(abuseipdb_key))

        if virustotal_key:
            self.feeds.append(VirusTotalFeed(virustotal_key))

        if alienvault_key:
            self.feeds.append(AlienVaultOTXFeed(alienvault_key))

        self.cache = ThreatCache(ttl=cache_ttl)

        logger.info(f"Initialized threat intelligence with {len(self.feeds)} feeds")

    async def lookup(self, event: dict[str, Any]) -> float:
        """Lookup threat indicators in feeds.

        Args:
            event: Security event with potential indicators

        Returns:
            Aggregated threat score (0-1)
        """
        scores = []

        # Check IPs
        if event.get("destination_ip"):
            ip_score = await self._lookup_ip(event["destination_ip"])
            if ip_score > 0:
                scores.append(ip_score)

        # Check domains
        if event.get("destination_domain"):
            domain_score = await self._lookup_domain(event["destination_domain"])
            if domain_score > 0:
                scores.append(domain_score)

        # Check file hashes
        if event.get("file_hash"):
            hash_score = await self._lookup_hash(event["file_hash"])
            if hash_score > 0:
                scores.append(hash_score)

        # Return maximum score (most severe)
        return max(scores) if scores else 0.0

    async def _lookup_ip(self, ip: str) -> float:
        """Lookup IP with caching.

        Args:
            ip: IP address

        Returns:
            Threat score (0-1)
        """
        # Check cache
        cache_key = f"ip:{ip}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            logger.debug(f"IP {ip} found in cache: {cached:.2f}")
            return cached

        # Query feeds in parallel
        tasks = [feed.lookup_ip(ip) for feed in self.feeds]
        scores = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and get max score
        valid_scores = [s for s in scores if isinstance(s, int | float)]
        score = max(valid_scores) if valid_scores else 0.0

        # Cache result
        self.cache.set(cache_key, score)

        logger.debug(f"IP {ip} threat score: {score:.2f}")
        return score

    async def _lookup_domain(self, domain: str) -> float:
        """Lookup domain with caching.

        Args:
            domain: Domain name

        Returns:
            Threat score (0-1)
        """
        # Check cache
        cache_key = f"domain:{domain}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            logger.debug(f"Domain {domain} found in cache: {cached:.2f}")
            return cached

        # Query feeds in parallel
        tasks = [feed.lookup_domain(domain) for feed in self.feeds]
        scores = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and get max score
        valid_scores = [s for s in scores if isinstance(s, int | float)]
        score = max(valid_scores) if valid_scores else 0.0

        # Cache result
        self.cache.set(cache_key, score)

        logger.debug(f"Domain {domain} threat score: {score:.2f}")
        return score

    async def _lookup_hash(self, file_hash: str) -> float:
        """Lookup file hash with caching.

        Args:
            file_hash: File hash

        Returns:
            Threat score (0-1)
        """
        # Check cache
        cache_key = f"hash:{file_hash}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            logger.debug(f"Hash {file_hash} found in cache: {cached:.2f}")
            return cached

        # Query feeds in parallel
        tasks = [feed.lookup_hash(file_hash) for feed in self.feeds]
        scores = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and get max score
        valid_scores = [s for s in scores if isinstance(s, int | float)]
        score = max(valid_scores) if valid_scores else 0.0

        # Cache result
        self.cache.set(cache_key, score)

        logger.debug(f"Hash {file_hash} threat score: {score:.2f}")
        return score

    async def close(self) -> None:
        """Close all feed connections."""
        for feed in self.feeds:
            await feed.close()

    def clear_cache(self) -> None:
        """Clear threat intelligence cache."""
        self.cache.clear()
        logger.info("Cleared threat intelligence cache")
