"""Parser forense para AnyDesk (ad.trace, ad_svc.trace, connection_trace.txt)."""

from .parser import AnyDeskParser
from .ad_trace import parse_ad_trace
from .connection_trace import parse_connection_trace

__all__ = ["AnyDeskParser", "parse_ad_trace", "parse_connection_trace"]
