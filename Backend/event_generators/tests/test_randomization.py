"""
Tests for the randomization service
"""
import ipaddress
import pytest
import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from shared.randomization import Randomizer, PersonInfo
except ImportError as e:
    pytest.skip(f"Cannot import randomization: {e}", allow_module_level=True)


class TestInternalIP:
    """Test internal/private IP generation"""

    def test_default_returns_private_ip(self):
        r = Randomizer(seed=1)
        ip = r.internal_ip()
        addr = ipaddress.IPv4Address(ip)
        assert addr.is_private

    def test_many_ips_all_private(self):
        r = Randomizer(seed=42)
        for _ in range(200):
            addr = ipaddress.IPv4Address(r.internal_ip())
            assert addr.is_private, f"{addr} is not private"

    def test_cidr_constraint(self):
        r = Randomizer(seed=10)
        network = ipaddress.IPv4Network("10.50.0.0/16")
        for _ in range(100):
            ip = r.internal_ip(cidr="10.50.0.0/16")
            addr = ipaddress.IPv4Address(ip)
            assert addr in network, f"{addr} not in 10.50.0.0/16"

    def test_cidr_small_subnet(self):
        r = Randomizer(seed=5)
        network = ipaddress.IPv4Network("192.168.1.0/24")
        for _ in range(50):
            ip = r.internal_ip(cidr="192.168.1.0/24")
            addr = ipaddress.IPv4Address(ip)
            assert addr in network

    def test_cidr_slash_30(self):
        """A /30 has 4 addresses, 2 usable (excluding network + broadcast)."""
        r = Randomizer(seed=7)
        network = ipaddress.IPv4Network("10.0.0.0/30")
        for _ in range(20):
            ip = r.internal_ip(cidr="10.0.0.0/30")
            addr = ipaddress.IPv4Address(ip)
            assert addr in network
            # Should not be network or broadcast
            assert addr != network.network_address
            assert addr != network.broadcast_address

    def test_returns_string(self):
        r = Randomizer()
        ip = r.internal_ip()
        assert isinstance(ip, str)
        # Parseable
        ipaddress.IPv4Address(ip)


class TestExternalIP:
    """Test external/public IP generation"""

    def test_returns_public_ip(self):
        r = Randomizer(seed=1)
        ip = r.external_ip()
        addr = ipaddress.IPv4Address(ip)
        assert not addr.is_private
        assert not addr.is_reserved
        assert not addr.is_loopback

    def test_many_ips_all_public(self):
        r = Randomizer(seed=42)
        for _ in range(200):
            ip = r.external_ip()
            addr = ipaddress.IPv4Address(ip)
            assert not addr.is_private, f"{addr} is private"
            assert not addr.is_loopback, f"{addr} is loopback"

    def test_returns_string(self):
        r = Randomizer()
        ip = r.external_ip()
        assert isinstance(ip, str)
        ipaddress.IPv4Address(ip)


class TestIPConvenience:
    """Test the ip() convenience wrapper"""

    def test_internal_flag(self):
        r = Randomizer(seed=1)
        ip = r.ip(internal=True)
        assert ipaddress.IPv4Address(ip).is_private

    def test_external_flag(self):
        r = Randomizer(seed=1)
        ip = r.ip(internal=False)
        assert not ipaddress.IPv4Address(ip).is_private

    def test_cidr_passthrough(self):
        r = Randomizer(seed=1)
        network = ipaddress.IPv4Network("172.16.5.0/24")
        ip = r.ip(internal=True, cidr="172.16.5.0/24")
        assert ipaddress.IPv4Address(ip) in network


class TestPerson:
    """Test person/name generation"""

    def test_returns_person_info(self):
        r = Randomizer(seed=1)
        p = r.person()
        assert isinstance(p, PersonInfo)

    def test_person_fields(self):
        r = Randomizer(seed=1)
        p = r.person(domain="starfleet.corp")
        assert p.first_name
        assert p.last_name
        assert p.email.endswith("@starfleet.corp")
        assert p.username == f"{p.first_name.lower()}.{p.last_name.lower()}"
        assert p.display_name == f"{p.first_name} {p.last_name}"
        assert p.department
        assert p.role
        assert len(p.location) == 3

    def test_custom_department_and_role(self):
        r = Randomizer(seed=1)
        p = r.person(department="Security", role="Analyst")
        assert p.department == "Security"
        assert p.role == "Analyst"

    def test_unique_names(self):
        r = Randomizer(seed=42)
        people = [r.person() for _ in range(50)]
        usernames = [p.username for p in people]
        assert len(set(usernames)) == len(usernames), "Duplicate usernames generated"

    def test_to_dict(self):
        r = Randomizer(seed=1)
        p = r.person()
        d = p.to_dict()
        assert isinstance(d, dict)
        assert "first_name" in d
        assert "last_name" in d
        assert "email" in d
        assert "username" in d
        assert "display_name" in d
        assert "department" in d
        assert "role" in d
        assert "city" in d
        assert "state" in d
        assert "country" in d


class TestNameHelpers:
    """Test individual name helper methods"""

    def test_first_name(self):
        r = Randomizer(seed=1)
        name = r.first_name()
        assert isinstance(name, str)
        assert len(name) > 0

    def test_last_name(self):
        r = Randomizer(seed=1)
        name = r.last_name()
        assert isinstance(name, str)
        assert len(name) > 0

    def test_email(self):
        r = Randomizer(seed=1)
        email = r.email(first="Jean", last="Picard", domain="starfleet.corp")
        assert email == "jean.picard@starfleet.corp"

    def test_email_random(self):
        r = Randomizer(seed=1)
        email = r.email()
        assert "@company.com" in email
        assert "." in email.split("@")[0]

    def test_username(self):
        r = Randomizer(seed=1)
        u = r.username(first="Jean", last="Picard")
        assert u == "jean.picard"

    def test_username_random(self):
        r = Randomizer(seed=1)
        u = r.username()
        assert isinstance(u, str)
        assert "." in u


class TestContext:
    """Test assignment caching / context"""

    def test_assign_caches_value(self):
        r = Randomizer(seed=1)
        ip1 = r.assign("victim", "ip", r.internal_ip)
        ip2 = r.assign("victim", "ip", r.internal_ip)
        assert ip1 == ip2

    def test_assign_different_entities(self):
        r = Randomizer(seed=1)
        ip1 = r.assign("victim", "ip", r.internal_ip)
        ip2 = r.assign("attacker", "ip", r.external_ip)
        assert ip1 != ip2

    def test_assign_different_fields(self):
        r = Randomizer(seed=1)
        ip = r.assign("victim", "ip", r.internal_ip)
        name = r.assign("victim", "name", r.first_name)
        assert isinstance(ip, str)
        assert isinstance(name, str)
        assert "." in ip  # IP has dots
        assert "." not in name  # Name doesn't

    def test_get_returns_cached(self):
        r = Randomizer(seed=1)
        ip = r.assign("victim", "ip", r.internal_ip)
        assert r.get("victim", "ip") == ip

    def test_get_returns_default_when_missing(self):
        r = Randomizer(seed=1)
        assert r.get("nobody", "ip") is None
        assert r.get("nobody", "ip", "fallback") == "fallback"

    def test_set_manual(self):
        r = Randomizer(seed=1)
        r.set("c2", "ip", "185.234.72.156")
        assert r.get("c2", "ip") == "185.234.72.156"

    def test_assign_with_kwargs(self):
        r = Randomizer(seed=1)
        ip = r.assign("server", "ip", r.internal_ip, cidr="10.50.0.0/16")
        addr = ipaddress.IPv4Address(ip)
        assert addr in ipaddress.IPv4Network("10.50.0.0/16")

    def test_context_snapshot(self):
        r = Randomizer(seed=1)
        r.assign("victim", "ip", r.internal_ip)
        r.assign("victim", "name", r.first_name)
        snap = r.context_snapshot()
        assert "victim" in snap
        assert "ip" in snap["victim"]
        assert "name" in snap["victim"]

    def test_reset_clears_context(self):
        r = Randomizer(seed=1)
        r.assign("victim", "ip", r.internal_ip)
        r.reset()
        assert r.get("victim", "ip") is None


class TestSeedReproducibility:
    """Test that seeded Randomizer produces deterministic results"""

    def test_same_seed_same_ips(self):
        r1 = Randomizer(seed=99)
        r2 = Randomizer(seed=99)
        ips1 = [r1.internal_ip() for _ in range(10)]
        ips2 = [r2.internal_ip() for _ in range(10)]
        assert ips1 == ips2

    def test_same_seed_same_external_ips(self):
        r1 = Randomizer(seed=99)
        r2 = Randomizer(seed=99)
        ips1 = [r1.external_ip() for _ in range(10)]
        ips2 = [r2.external_ip() for _ in range(10)]
        assert ips1 == ips2

    def test_same_seed_same_persons(self):
        r1 = Randomizer(seed=99)
        r2 = Randomizer(seed=99)
        p1 = r1.person()
        p2 = r2.person()
        assert p1.email == p2.email
        assert p1.department == p2.department

    def test_different_seeds_different_results(self):
        r1 = Randomizer(seed=1)
        r2 = Randomizer(seed=2)
        ips1 = [r1.internal_ip() for _ in range(5)]
        ips2 = [r2.internal_ip() for _ in range(5)]
        assert ips1 != ips2

    def test_no_seed_is_random(self):
        r1 = Randomizer()
        r2 = Randomizer()
        # Very unlikely to be the same with no seed
        ips1 = [r1.internal_ip() for _ in range(10)]
        ips2 = [r2.internal_ip() for _ in range(10)]
        assert ips1 != ips2


class TestPerformance:
    """Test generation performance"""

    def test_batch_ip_generation(self):
        import time
        r = Randomizer(seed=1)
        start = time.time()
        for _ in range(1000):
            r.internal_ip()
            r.external_ip()
        elapsed = time.time() - start
        assert elapsed < 2.0, f"1000 IP pairs took {elapsed:.2f}s"

    def test_batch_person_generation(self):
        import time
        r = Randomizer(seed=1)
        start = time.time()
        for _ in range(100):
            r.person(unique=False)
        elapsed = time.time() - start
        assert elapsed < 2.0, f"100 persons took {elapsed:.2f}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
