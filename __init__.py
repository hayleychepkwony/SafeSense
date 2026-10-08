"""SafeSense: an explainable phishing checker."""
from .checks import Finding, Report, analyze, analyze_url, registered_domain

__all__ = ["Finding", "Report", "analyze", "analyze_url", "registered_domain"]
__version__ = "0.1.0"
