"""Registre des sondes disponibles (id -> instance)."""
from __future__ import annotations

from redteam.tools.probes.base import Probe
from redteam.tools.probes.security_headers import SecurityHeadersProbe
from redteam.tools.probes.version_disclosure import VersionDisclosureProbe
from redteam.tools.probes.exposed_endpoints import ExposedEndpointsProbe
from redteam.tools.probes.reflected_input import ReflectedInputProbe

PROBES: dict[str, Probe] = {
    p.id: p for p in (
        SecurityHeadersProbe(), VersionDisclosureProbe(),
        ExposedEndpointsProbe(), ReflectedInputProbe(),
    )
}


def get_probe(probe_id: str) -> Probe:
    return PROBES[probe_id]
