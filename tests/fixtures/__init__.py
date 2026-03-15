"""
Fixtures for Proxilion tests.

This package provides reusable fixtures for creating test data:
- users.py: User context fixtures
- tool_calls.py: Tool call request fixtures
- provider_responses.py: Provider response fixtures
"""

from tests.fixtures.provider_responses import (
    make_anthropic_response,
    make_gemini_response,
    make_openai_response,
)
from tests.fixtures.tool_calls import (
    make_attack_sequence,
    make_normal_crud_sequence,
    make_path_traversal_attempt,
    make_safe_search,
    make_sql_injection_attempt,
)
from tests.fixtures.users import (
    make_admin_user,
    make_analyst_user,
    make_external_partner,
    make_guest_user,
    make_multi_role_user,
    make_service_account,
    make_suspended_user,
    make_viewer_user,
)

__all__ = [
    # Users
    "make_admin_user",
    "make_analyst_user",
    "make_viewer_user",
    "make_guest_user",
    "make_service_account",
    "make_multi_role_user",
    "make_external_partner",
    "make_suspended_user",
    # Tool calls
    "make_safe_search",
    "make_sql_injection_attempt",
    "make_path_traversal_attempt",
    "make_normal_crud_sequence",
    "make_attack_sequence",
    # Provider responses
    "make_openai_response",
    "make_anthropic_response",
    "make_gemini_response",
]
