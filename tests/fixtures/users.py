"""
User context fixtures for testing.

Provides factory functions for creating various types of user contexts
with different roles, permissions, and attributes.
"""

from __future__ import annotations

from proxilion.types import UserContext


def make_admin_user(user_id: str = "admin_001") -> UserContext:
    """
    Create an admin user with full permissions.

    Args:
        user_id: Optional custom user ID.

    Returns:
        UserContext with admin role and high clearance.
    """
    return UserContext(
        user_id=user_id,
        roles=["admin", "user", "editor"],
        session_id=f"session_{user_id}",
        attributes={
            "department": "engineering",
            "clearance": "high",
            "title": "System Administrator",
            "region": "us-east-1",
        },
    )


def make_analyst_user(user_id: str = "analyst_001") -> UserContext:
    """
    Create an analyst user with data access permissions.

    Args:
        user_id: Optional custom user ID.

    Returns:
        UserContext with analyst role and medium clearance.
    """
    return UserContext(
        user_id=user_id,
        roles=["analyst", "user"],
        session_id=f"session_{user_id}",
        attributes={
            "department": "data_science",
            "clearance": "medium",
            "title": "Data Analyst",
            "region": "us-west-2",
        },
    )


def make_viewer_user(user_id: str = "viewer_001") -> UserContext:
    """
    Create a viewer user with read-only permissions.

    Args:
        user_id: Optional custom user ID.

    Returns:
        UserContext with viewer role.
    """
    return UserContext(
        user_id=user_id,
        roles=["viewer", "user"],
        session_id=f"session_{user_id}",
        attributes={
            "department": "marketing",
            "clearance": "low",
            "title": "Marketing Analyst",
            "region": "eu-west-1",
        },
    )


def make_guest_user(user_id: str = "guest_001") -> UserContext:
    """
    Create a guest user with minimal permissions.

    Args:
        user_id: Optional custom user ID.

    Returns:
        UserContext with guest role and no special attributes.
    """
    return UserContext(
        user_id=user_id,
        roles=["guest"],
        session_id=None,  # Guests may not have sessions
        attributes={
            "account_type": "trial",
            "expires_at": "2026-12-31",
        },
    )


def make_service_account(service_id: str = "service_001") -> UserContext:
    """
    Create a service account for automated processes.

    Args:
        service_id: Optional custom service ID.

    Returns:
        UserContext with service role.
    """
    return UserContext(
        user_id=service_id,
        roles=["service", "automation"],
        session_id=f"service_session_{service_id}",
        attributes={
            "service_type": "scheduled_job",
            "owner": "platform_team",
            "automated": True,
            "rate_limit_tier": "high",
        },
    )


def make_multi_role_user(user_id: str = "multi_001") -> UserContext:
    """
    Create a user with multiple roles for testing role combinations.

    Args:
        user_id: Optional custom user ID.

    Returns:
        UserContext with multiple roles.
    """
    return UserContext(
        user_id=user_id,
        roles=["user", "editor", "reviewer", "analyst", "moderator"],
        session_id=f"session_{user_id}",
        attributes={
            "department": "product",
            "clearance": "medium",
            "title": "Senior Product Manager",
            "region": "us-central",
            "teams": ["platform", "security", "data"],
        },
    )


def make_external_partner(partner_id: str = "partner_001") -> UserContext:
    """
    Create an external partner user with limited access.

    Args:
        partner_id: Optional custom partner ID.

    Returns:
        UserContext with partner role.
    """
    return UserContext(
        user_id=partner_id,
        roles=["partner", "external"],
        session_id=f"partner_session_{partner_id}",
        attributes={
            "organization": "Acme Corp",
            "contract_tier": "gold",
            "clearance": "restricted",
            "access_scope": "api_only",
            "region": "eu-central",
        },
    )


def make_suspended_user(user_id: str = "suspended_001") -> UserContext:
    """
    Create a suspended user for testing access denial.

    Args:
        user_id: Optional custom user ID.

    Returns:
        UserContext with suspended flag in attributes.
    """
    return UserContext(
        user_id=user_id,
        roles=["user"],
        session_id=None,  # No active session
        attributes={
            "status": "suspended",
            "suspended_at": "2026-01-15",
            "reason": "Terms of service violation",
            "department": "engineering",
        },
    )
