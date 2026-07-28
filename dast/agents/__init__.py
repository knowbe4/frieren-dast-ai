"""
Import all agent modules to trigger Coordinator.register() calls.
This module must be imported before run_active_checks() is called.
"""

from dast.agents import (  # noqa: F401
    auth_agent,
    blazor_agent,
    cache_poisoning_agent,
    cmdi_agent,
    business_logic_agent,
    cross_session_idor_agent,
    csrf_agent,
    discovery_agent,
    file_read_agent,
    graphql_agent,
    idor_agent,
    llm_injection_agent,
    mfa_agent,
    nosql_agent,
    open_redirect_agent,
    prototype_pollution_agent,
    secrets_agent,
    sqli_agent,
    ssti_agent,
    ssrf_agent,
    xss_agent,
    xxe_agent,
)
