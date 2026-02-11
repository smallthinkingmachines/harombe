"""Tests for threat intelligence integration."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from harombe.security.ml.threat_intel import (
    AbuseIPDBFeed,
    AlienVaultOTXFeed,
    ThreatCache,
    ThreatIntelligence,
    VirusTotalFeed,
)


@pytest.fixture
def threat_cache():
    """Create threat cache instance."""
    return ThreatCache(ttl=60)


@pytest.fixture
def mock_abuseipdb():
    """Create mock AbuseIPDB feed."""
    return AbuseIPDBFeed(api_key="test_key")


@pytest.fixture
def mock_virustotal():
    """Create mock VirusTotal feed."""
    return VirusTotalFeed(api_key="test_key")


@pytest.fixture
def mock_alienvault():
    """Create mock AlienVault feed."""
    return AlienVaultOTXFeed(api_key="test_key")


class TestThreatCache:
    """Test threat intelligence caching."""

    def test_initialization(self, threat_cache):
        """Test cache initialization."""
        assert threat_cache.ttl == 60
        assert len(threat_cache.cache) == 0

    def test_cache_set_and_get(self, threat_cache):
        """Test setting and getting cached values."""
        threat_cache.set("test_key", 0.8)

        result = threat_cache.get("test_key")
        assert result == 0.8

    def test_cache_miss(self, threat_cache):
        """Test cache miss returns None."""
        result = threat_cache.get("nonexistent")
        assert result is None

    def test_cache_expiration(self):
        """Test cache entries expire after TTL."""
        cache = ThreatCache(ttl=1)  # 1 second TTL
        cache.set("test_key", 0.5)

        # Should be cached
        assert cache.get("test_key") == 0.5

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        assert cache.get("test_key") is None

    def test_cache_clear(self, threat_cache):
        """Test clearing cache."""
        threat_cache.set("key1", 0.5)
        threat_cache.set("key2", 0.7)

        threat_cache.clear()

        assert len(threat_cache.cache) == 0
        assert threat_cache.get("key1") is None
        assert threat_cache.get("key2") is None

    def test_cleanup_expired(self):
        """Test cleanup of expired entries."""
        cache = ThreatCache(ttl=1)
        cache.set("key1", 0.5)
        time.sleep(1.1)
        cache.set("key2", 0.7)

        # key1 should be expired, key2 should not
        cache.cleanup_expired()

        assert cache.get("key1") is None
        assert cache.get("key2") == 0.7


class TestAbuseIPDBFeed:
    """Test AbuseIPDB feed integration."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_abuseipdb):
        """Test AbuseIPDB feed initialization."""
        assert mock_abuseipdb.name == "AbuseIPDB"
        assert mock_abuseipdb.api_key == "test_key"

    @pytest.mark.asyncio
    async def test_lookup_ip_success(self, mock_abuseipdb):
        """Test successful IP lookup."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"abuseConfidenceScore": 75}}

        with patch.object(mock_abuseipdb.client, "get", return_value=mock_response):
            score = await mock_abuseipdb.lookup_ip("1.2.3.4")

        assert score == 0.75  # 75/100

    @pytest.mark.asyncio
    async def test_lookup_ip_no_api_key(self):
        """Test IP lookup without API key."""
        feed = AbuseIPDBFeed(api_key=None)
        score = await feed.lookup_ip("1.2.3.4")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_lookup_ip_api_error(self, mock_abuseipdb):
        """Test IP lookup with API error."""
        mock_response = MagicMock()
        mock_response.status_code = 429  # Rate limited
        mock_response.text = "Rate limit exceeded"

        with patch.object(mock_abuseipdb.client, "get", return_value=mock_response):
            score = await mock_abuseipdb.lookup_ip("1.2.3.4")

        assert score == 0.0

    @pytest.mark.asyncio
    async def test_lookup_domain_not_supported(self, mock_abuseipdb):
        """Test domain lookup (not supported by AbuseIPDB)."""
        score = await mock_abuseipdb.lookup_domain("evil.com")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_lookup_hash_not_supported(self, mock_abuseipdb):
        """Test hash lookup (not supported by AbuseIPDB)."""
        score = await mock_abuseipdb.lookup_hash("abc123")
        assert score == 0.0


class TestVirusTotalFeed:
    """Test VirusTotal feed integration."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_virustotal):
        """Test VirusTotal feed initialization."""
        assert mock_virustotal.name == "VirusTotal"
        assert mock_virustotal.api_key == "test_key"
        assert mock_virustotal.min_request_interval == 15.0  # Free tier

    @pytest.mark.asyncio
    async def test_lookup_ip_malicious(self, mock_virustotal):
        """Test IP lookup with malicious result."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 2,
                        "harmless": 70,
                        "undetected": 20,
                    }
                }
            }
        }

        with patch.object(mock_virustotal.client, "get", return_value=mock_response):
            score = await mock_virustotal.lookup_ip("1.2.3.4")

        # 8 malicious out of 100 total
        assert score == 0.08

    @pytest.mark.asyncio
    async def test_lookup_domain_suspicious(self, mock_virustotal):
        """Test domain lookup with suspicious result."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 10,
                        "harmless": 80,
                        "undetected": 5,
                    }
                }
            }
        }

        with patch.object(mock_virustotal.client, "get", return_value=mock_response):
            score = await mock_virustotal.lookup_domain("evil.xyz")

        # (5 malicious + 10*0.5 suspicious) / 100
        assert score == 0.1

    @pytest.mark.asyncio
    async def test_lookup_hash_clean(self, mock_virustotal):
        """Test hash lookup with clean result."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 95,
                        "undetected": 5,
                    }
                }
            }
        }

        with patch.object(mock_virustotal.client, "get", return_value=mock_response):
            score = await mock_virustotal.lookup_hash("abc123")

        assert score == 0.0


class TestAlienVaultOTXFeed:
    """Test AlienVault OTX feed integration."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_alienvault):
        """Test AlienVault feed initialization."""
        assert mock_alienvault.name == "AlienVault OTX"
        assert mock_alienvault.api_key == "test_key"

    @pytest.mark.asyncio
    async def test_lookup_ip_threat(self, mock_alienvault):
        """Test IP lookup with threat."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "reputation": {"threat_score": 5}  # Out of 7
        }

        with patch.object(mock_alienvault.client, "get", return_value=mock_response):
            score = await mock_alienvault.lookup_ip("1.2.3.4")

        assert abs(score - 5.0 / 7.0) < 0.01

    @pytest.mark.asyncio
    async def test_lookup_domain_threat(self, mock_alienvault):
        """Test domain lookup with threat."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"reputation": {"threat_score": 3}}

        with patch.object(mock_alienvault.client, "get", return_value=mock_response):
            score = await mock_alienvault.lookup_domain("evil.com")

        assert abs(score - 3.0 / 7.0) < 0.01

    @pytest.mark.asyncio
    async def test_lookup_hash_malware(self, mock_alienvault):
        """Test hash lookup with malware."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"analysis": {"malware": {"detections": ["trojan"]}}}

        with patch.object(mock_alienvault.client, "get", return_value=mock_response):
            score = await mock_alienvault.lookup_hash("abc123")

        assert score == 1.0  # Confirmed malware


class TestThreatIntelligence:
    """Test integrated threat intelligence."""

    def test_initialization_no_keys(self):
        """Test initialization with no API keys."""
        intel = ThreatIntelligence()
        assert len(intel.feeds) == 0

    def test_initialization_with_keys(self):
        """Test initialization with API keys."""
        intel = ThreatIntelligence(
            abuseipdb_key="key1",
            virustotal_key="key2",
            alienvault_key="key3",
        )
        assert len(intel.feeds) == 3

    @pytest.mark.asyncio
    async def test_lookup_ip_event(self):
        """Test lookup with IP in event."""
        intel = ThreatIntelligence(abuseipdb_key="test_key")

        # Mock the _lookup_ip method
        with patch.object(intel, "_lookup_ip", return_value=0.8) as mock_lookup:
            event = {"destination_ip": "1.2.3.4"}
            score = await intel.lookup(event)

            mock_lookup.assert_called_once_with("1.2.3.4")
            assert score == 0.8

    @pytest.mark.asyncio
    async def test_lookup_domain_event(self):
        """Test lookup with domain in event."""
        intel = ThreatIntelligence(virustotal_key="test_key")

        with patch.object(intel, "_lookup_domain", return_value=0.6) as mock_lookup:
            event = {"destination_domain": "evil.xyz"}
            score = await intel.lookup(event)

            mock_lookup.assert_called_once_with("evil.xyz")
            assert score == 0.6

    @pytest.mark.asyncio
    async def test_lookup_hash_event(self):
        """Test lookup with file hash in event."""
        intel = ThreatIntelligence(virustotal_key="test_key")

        with patch.object(intel, "_lookup_hash", return_value=1.0) as mock_lookup:
            event = {"file_hash": "abc123"}
            score = await intel.lookup(event)

            mock_lookup.assert_called_once_with("abc123")
            assert score == 1.0

    @pytest.mark.asyncio
    async def test_lookup_multiple_indicators(self):
        """Test lookup with multiple threat indicators."""
        intel = ThreatIntelligence(abuseipdb_key="test_key")

        with (
            patch.object(intel, "_lookup_ip", return_value=0.3),
            patch.object(intel, "_lookup_domain", return_value=0.9),
        ):
            event = {
                "destination_ip": "1.2.3.4",
                "destination_domain": "evil.xyz",
            }
            score = await intel.lookup(event)

            # Should return max score
            assert score == 0.9

    @pytest.mark.asyncio
    async def test_lookup_no_indicators(self):
        """Test lookup with no threat indicators."""
        intel = ThreatIntelligence(abuseipdb_key="test_key")

        event = {"event_type": "normal_operation"}
        score = await intel.lookup(event)

        assert score == 0.0

    @pytest.mark.asyncio
    async def test_caching(self):
        """Test threat intelligence caching."""
        intel = ThreatIntelligence(abuseipdb_key="test_key")

        # Mock feed lookup
        mock_feed = MagicMock()
        mock_feed.lookup_ip = AsyncMock(return_value=0.7)
        intel.feeds = [mock_feed]

        # First lookup
        score1 = await intel._lookup_ip("1.2.3.4")
        assert score1 == 0.7
        assert mock_feed.lookup_ip.call_count == 1

        # Second lookup (should use cache)
        score2 = await intel._lookup_ip("1.2.3.4")
        assert score2 == 0.7
        assert mock_feed.lookup_ip.call_count == 1  # Not called again

    @pytest.mark.asyncio
    async def test_parallel_feed_queries(self):
        """Test querying multiple feeds in parallel."""
        intel = ThreatIntelligence(
            abuseipdb_key="key1",
            virustotal_key="key2",
        )

        # Mock feeds
        feed1 = MagicMock()
        feed1.lookup_ip = AsyncMock(return_value=0.5)
        feed2 = MagicMock()
        feed2.lookup_ip = AsyncMock(return_value=0.8)
        intel.feeds = [feed1, feed2]

        score = await intel._lookup_ip("1.2.3.4")

        # Should return max score from both feeds
        assert score == 0.8
        assert feed1.lookup_ip.called
        assert feed2.lookup_ip.called

    @pytest.mark.asyncio
    async def test_feed_exception_handling(self):
        """Test handling of feed exceptions."""
        intel = ThreatIntelligence(abuseipdb_key="test_key")

        # Mock feed that raises exception
        mock_feed = MagicMock()
        mock_feed.lookup_ip = AsyncMock(side_effect=Exception("API error"))
        intel.feeds = [mock_feed]

        # Should not raise, return 0.0
        score = await intel._lookup_ip("1.2.3.4")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_clear_cache(self):
        """Test clearing cache."""
        intel = ThreatIntelligence(abuseipdb_key="test_key")

        # Cache some data
        intel.cache.set("ip:1.2.3.4", 0.7)
        assert intel.cache.get("ip:1.2.3.4") == 0.7

        # Clear cache
        intel.clear_cache()
        assert intel.cache.get("ip:1.2.3.4") is None


@pytest.mark.integration
class TestThreatIntelIntegration:
    """Integration tests for threat intelligence."""

    @pytest.mark.asyncio
    async def test_end_to_end_lookup(self):
        """Test end-to-end threat lookup."""
        # Create intel without real API keys (will return 0.0)
        intel = ThreatIntelligence()

        event = {
            "destination_ip": "1.2.3.4",
            "destination_domain": "example.com",
        }

        score = await intel.lookup(event)
        assert score == 0.0  # No feeds configured

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Test rate limiting works correctly."""
        feed = AbuseIPDBFeed(api_key="test_key")

        start_time = time.time()

        # Make multiple requests
        await feed._rate_limit()
        await feed._rate_limit()

        elapsed = time.time() - start_time

        # Should take at least 1 second (min_request_interval)
        assert elapsed >= 1.0


# ---------------------------------------------------------------------------
# New edge-case and coverage tests
# ---------------------------------------------------------------------------


class TestFeedEdgeCases:
    """Test edge cases for threat feeds."""

    @pytest.mark.asyncio
    async def test_virustotal_ip_no_key(self):
        """VirusTotal IP lookup returns 0.0 when no API key is set."""
        feed = VirusTotalFeed(api_key=None)
        score = await feed.lookup_ip("1.2.3.4")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_virustotal_domain_no_key(self):
        """VirusTotal domain lookup returns 0.0 when no API key is set."""
        feed = VirusTotalFeed(api_key=None)
        score = await feed.lookup_domain("evil.com")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_virustotal_hash_no_key(self):
        """VirusTotal hash lookup returns 0.0 when no API key is set."""
        feed = VirusTotalFeed(api_key=None)
        score = await feed.lookup_hash("abc123")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_alienvault_ip_no_key(self):
        """AlienVault IP lookup returns 0.0 when no API key is set."""
        feed = AlienVaultOTXFeed(api_key=None)
        score = await feed.lookup_ip("1.2.3.4")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_alienvault_domain_no_key(self):
        """AlienVault domain lookup returns 0.0 when no API key is set."""
        feed = AlienVaultOTXFeed(api_key=None)
        score = await feed.lookup_domain("evil.com")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_alienvault_hash_no_key(self):
        """AlienVault hash lookup returns 0.0 when no API key is set."""
        feed = AlienVaultOTXFeed(api_key=None)
        score = await feed.lookup_hash("abc123")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_virustotal_ip_exception(self):
        """VirusTotal IP lookup returns 0.0 on network exception."""
        feed = VirusTotalFeed(api_key="test_key")
        with patch.object(feed.client, "get", side_effect=Exception("Network error")):
            score = await feed.lookup_ip("1.2.3.4")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_virustotal_domain_api_error(self):
        """VirusTotal domain lookup returns 0.0 on HTTP error status."""
        feed = VirusTotalFeed(api_key="test_key")
        mock_response = MagicMock()
        mock_response.status_code = 403
        with patch.object(feed.client, "get", return_value=mock_response):
            score = await feed.lookup_domain("evil.com")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_alienvault_ip_api_error(self):
        """AlienVault IP lookup returns 0.0 on HTTP error status."""
        feed = AlienVaultOTXFeed(api_key="test_key")
        mock_response = MagicMock()
        mock_response.status_code = 500
        with patch.object(feed.client, "get", return_value=mock_response):
            score = await feed.lookup_ip("1.2.3.4")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_abuseipdb_exception(self):
        """AbuseIPDB lookup returns 0.0 on exception (line 175)."""
        feed = AbuseIPDBFeed(api_key="test_key")
        with patch.object(feed.client, "get", side_effect=Exception("Timeout")):
            score = await feed.lookup_ip("1.2.3.4")
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_feed_close(self):
        """ThreatFeed.close() calls client.aclose()."""
        feed = AbuseIPDBFeed(api_key="test_key")
        with patch.object(feed.client, "aclose", new_callable=AsyncMock) as mock_close:
            await feed.close()
            mock_close.assert_called_once()

    @pytest.mark.asyncio
    async def test_threat_intel_close(self):
        """ThreatIntelligence.close() closes all feed connections."""
        intel = ThreatIntelligence(abuseipdb_key="key1", virustotal_key="key2")
        for feed in intel.feeds:
            feed.client = MagicMock()
            feed.client.aclose = AsyncMock()
        await intel.close()
        for feed in intel.feeds:
            feed.client.aclose.assert_called_once()


class TestThreatIntelLookupCaching:
    """Test caching paths for domain and hash lookups."""

    @pytest.mark.asyncio
    async def test_domain_caching(self):
        """Domain lookups are cached after the first query."""
        intel = ThreatIntelligence(virustotal_key="test_key")
        mock_feed = MagicMock()
        mock_feed.lookup_domain = AsyncMock(return_value=0.5)
        intel.feeds = [mock_feed]

        score1 = await intel._lookup_domain("evil.com")
        score2 = await intel._lookup_domain("evil.com")
        assert score1 == 0.5
        assert score2 == 0.5
        assert mock_feed.lookup_domain.call_count == 1  # Cached

    @pytest.mark.asyncio
    async def test_hash_caching(self):
        """Hash lookups are cached after the first query."""
        intel = ThreatIntelligence(virustotal_key="test_key")
        mock_feed = MagicMock()
        mock_feed.lookup_hash = AsyncMock(return_value=1.0)
        intel.feeds = [mock_feed]

        score1 = await intel._lookup_hash("abc123")
        score2 = await intel._lookup_hash("abc123")
        assert score1 == 1.0
        assert score2 == 1.0
        assert mock_feed.lookup_hash.call_count == 1

    @pytest.mark.asyncio
    async def test_virustotal_empty_stats(self):
        """VirusTotal returns 0.0 when analysis stats dict is empty."""
        feed = VirusTotalFeed(api_key="test_key")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"attributes": {"last_analysis_stats": {}}}}
        with patch.object(feed.client, "get", return_value=mock_response):
            score = await feed.lookup_ip("1.2.3.4")
        assert score == 0.0
