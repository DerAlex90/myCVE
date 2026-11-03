"""Independent matching library. The server extra is optional."""

from mycve.core.cpe import match_nvd
from mycve.core.cve import match_cve
from mycve.core.matching import match_osv
from mycve.core.models import Component, MatchResult
from mycve.core.priority import prioritize

__all__ = ["Component", "MatchResult", "match_osv", "match_cve", "match_nvd", "prioritize"]
__version__ = "0.2.0"
