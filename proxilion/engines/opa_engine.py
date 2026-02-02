"""
Open Policy Agent (OPA) policy engine integration for Proxilion.

This module provides integration with OPA, enabling policy-as-code
using the Rego policy language. OPA can run as a sidecar service
or be embedded in the application.

This implementation uses urllib (stdlib) to query an OPA server,
avoiding external HTTP library dependencies.
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

from proxilion.engines.base import (
    BasePolicyEngine,
    EngineCapabilities,
    PolicyEvaluationError,
    PolicyLoadError,
)
from proxilion.types import AuthorizationResult

if TYPE_CHECKING:
    from proxilion.types import UserContext

logger = logging.getLogger(__name__)


class OPAPolicyEngine(BasePolicyEngine):
    """
    Policy engine using Open Policy Agent (OPA) for authorization.

    OPA is a general-purpose policy engine that uses the Rego
    policy language. It can express complex authorization rules
    and is widely used in cloud-native environments.

    This engine queries an OPA server via REST API. The OPA server
    should be running and accessible at the configured endpoint.

    Configuration:
        - opa_url: Base URL of the OPA server (default: http://localhost:8181)
        - policy_path: OPA policy path for queries (default: v1/data/proxilion)
        - timeout: Request timeout in seconds (default: 5.0)
        - retry_count: Number of retries on failure (default: 3)
        - retry_delay: Delay between retries in seconds (default: 0.5)
        - fallback_allow: Whether to allow on OPA failure (default: False)

    Example:
        >>> engine = OPAPolicyEngine({
        ...     "opa_url": "http://localhost:8181",
        ...     "policy_path": "v1/data/proxilion/authz",
        ... })
        >>> result = engine.evaluate(user, "read", "document")

    OPA Policy Example (Rego):
        package proxilion.authz

        default allow := false

        allow {
            input.action == "read"
            "viewer" in input.user.roles
        }

        allow {
            input.action == "write"
            "editor" in input.user.roles
        }
    """

    name = "opa"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initialize the OPA policy engine.

        Args:
            config: Configuration options including opa_url and policy_path.
        """
        super().__init__(config)

        self.opa_url = self.get_config("opa_url", "http://localhost:8181")
        self.policy_path = self.get_config("policy_path", "v1/data/proxilion/authz")
        self.timeout = self.get_config("timeout", 5.0)
        self.retry_count = self.get_config("retry_count", 3)
        self.retry_delay = self.get_config("retry_delay", 0.5)
        self.fallback_allow = self.get_config("fallback_allow", False)

        # Build the full query URL
        self._query_url = f"{self.opa_url.rstrip('/')}/{self.policy_path.lstrip('/')}"

        self._initialized = True
        logger.debug(f"OPA engine initialized with URL: {self._query_url}")

    @property
    def capabilities(self) -> EngineCapabilities:
        """Get engine capabilities."""
        return EngineCapabilities(
            supports_async=True,
            supports_caching=False,  # OPA handles caching
            supports_explain=True,
            supports_partial_eval=True,
            supports_hot_reload=True,
            max_batch_size=1,
        )

    def _build_input(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Build the OPA input document.

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context.

        Returns:
            Dictionary to be sent as OPA input.
        """
        return {
            "input": {
                "user": {
                    "user_id": user.user_id,
                    "roles": user.roles,
                    "session_id": user.session_id,
                    "attributes": user.attributes,
                },
                "action": action,
                "resource": resource,
                "context": context or {},
            }
        }

    def _query_opa(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """
        Query the OPA server.

        Args:
            input_data: The input document for OPA.

        Returns:
            The OPA response as a dictionary.

        Raises:
            PolicyEvaluationError: If the query fails after retries.
        """
        request_data = json.dumps(input_data).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        last_error: Exception | None = None

        for attempt in range(self.retry_count):
            try:
                req = urllib.request.Request(
                    self._query_url,
                    data=request_data,
                    headers=headers,
                    method="POST",
                )

                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    response_data = response.read().decode("utf-8")
                    return json.loads(response_data)

            except urllib.error.HTTPError as e:
                last_error = e
                logger.warning(
                    f"OPA query failed (attempt {attempt + 1}/{self.retry_count}): "
                    f"HTTP {e.code}: {e.reason}"
                )
            except urllib.error.URLError as e:
                last_error = e
                logger.warning(
                    f"OPA query failed (attempt {attempt + 1}/{self.retry_count}): "
                    f"{e.reason}"
                )
            except TimeoutError as e:
                last_error = e
                logger.warning(
                    f"OPA query timeout (attempt {attempt + 1}/{self.retry_count})"
                )
            except json.JSONDecodeError as e:
                last_error = e
                logger.warning(
                    f"OPA response parse error (attempt {attempt + 1}/{self.retry_count})"
                )

            # Wait before retry (except on last attempt)
            if attempt < self.retry_count - 1:
                import time
                time.sleep(self.retry_delay * (attempt + 1))

        raise PolicyEvaluationError(
            f"OPA query failed after {self.retry_count} attempts: {last_error}",
            engine_name=self.name,
        )

    def _parse_opa_response(
        self,
        response: dict[str, Any],
        user: UserContext,
        action: str,
        resource: str,
    ) -> AuthorizationResult:
        """
        Parse the OPA response into an AuthorizationResult.

        OPA responses typically have a "result" key containing the
        policy decision. The structure depends on the policy.

        Expected response formats:
        1. Boolean: {"result": true}
        2. Object with allow: {"result": {"allow": true, "reason": "..."}}
        3. Object with deny reasons: {"result": {"allow": false, "deny": ["reason1"]}}

        Args:
            response: The OPA response.
            user: The user context.
            action: The action.
            resource: The resource.

        Returns:
            AuthorizationResult with the decision.
        """
        result = response.get("result")

        if result is None:
            # No result means policy doesn't define a decision
            return AuthorizationResult(
                allowed=False,
                reason="OPA policy returned no result (undefined)",
                policies_evaluated=["opa"],
            )

        # Handle boolean result
        if isinstance(result, bool):
            return AuthorizationResult(
                allowed=result,
                reason=f"OPA {'allowed' if result else 'denied'} {action} on {resource}",
                policies_evaluated=["opa"],
            )

        # Handle object result
        if isinstance(result, dict):
            allowed = result.get("allow", False)

            # Look for reason in various places
            reason = result.get("reason")
            if not reason and not allowed:
                deny_reasons = result.get("deny", [])
                if deny_reasons:
                    reason = "; ".join(str(r) for r in deny_reasons)
                else:
                    reason = f"OPA denied {action} on {resource}"
            elif not reason:
                reason = f"OPA allowed {action} on {resource}"

            return AuthorizationResult(
                allowed=bool(allowed),
                reason=reason,
                policies_evaluated=["opa"],
                metadata=result,
            )

        # Unknown format
        return AuthorizationResult(
            allowed=False,
            reason=f"Unexpected OPA result format: {type(result)}",
            policies_evaluated=["opa"],
        )

    def evaluate(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Evaluate an authorization request using OPA.

        Sends a query to the OPA server and parses the response.

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context for the decision.

        Returns:
            AuthorizationResult with the decision.
        """
        input_data = self._build_input(user, action, resource, context)

        logger.debug(f"OPA query: {action} on {resource} for user {user.user_id}")

        try:
            response = self._query_opa(input_data)
            return self._parse_opa_response(response, user, action, resource)

        except PolicyEvaluationError:
            if self.fallback_allow:
                logger.warning(
                    "OPA unavailable, using fallback_allow=True"
                )
                return AuthorizationResult(
                    allowed=True,
                    reason="OPA unavailable, fallback to allow",
                    policies_evaluated=["opa-fallback"],
                )
            raise

    async def evaluate_async(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> AuthorizationResult:
        """
        Async version of evaluate.

        Uses asyncio to make non-blocking HTTP requests.

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context.

        Returns:
            AuthorizationResult with the decision.
        """
        # Run sync version in thread pool
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self.evaluate, user, action, resource, context
        )

    def load_policies(self, source: str | Path) -> None:
        """
        Load policies into OPA.

        This method uploads Rego policies to the OPA server.

        Args:
            source: Path to a Rego file or directory of Rego files.
        """
        path = Path(source)

        if path.is_file():
            self._upload_policy(path)
        elif path.is_dir():
            for rego_file in path.glob("**/*.rego"):
                self._upload_policy(rego_file)
        else:
            raise PolicyLoadError(
                f"Policy source not found: {source}",
                engine_name=self.name,
            )

    def _upload_policy(self, policy_path: Path) -> None:
        """
        Upload a single policy file to OPA.

        Args:
            policy_path: Path to the Rego policy file.
        """
        policy_name = policy_path.stem
        policy_content = policy_path.read_text()

        url = f"{self.opa_url.rstrip('/')}/v1/policies/{policy_name}"

        try:
            req = urllib.request.Request(
                url,
                data=policy_content.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
                method="PUT",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status == 200:
                    logger.info(f"Uploaded policy: {policy_name}")
                else:
                    logger.warning(
                        f"Policy upload returned status {response.status}"
                    )

        except urllib.error.HTTPError as e:
            raise PolicyLoadError(
                f"Failed to upload policy {policy_name}: HTTP {e.code}",
                engine_name=self.name,
            ) from e
        except urllib.error.URLError as e:
            raise PolicyLoadError(
                f"Failed to connect to OPA: {e.reason}",
                engine_name=self.name,
            ) from e

    def health_check(self) -> bool:
        """
        Check if the OPA server is healthy.

        Returns:
            True if OPA is reachable and healthy.
        """
        health_url = f"{self.opa_url.rstrip('/')}/health"

        try:
            req = urllib.request.Request(health_url, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.status == 200
        except Exception:
            return False

    def explain(
        self,
        user: UserContext,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Get an explanation of the authorization decision.

        Uses OPA's explain feature to show how the decision was made.

        Args:
            user: The user context.
            action: The action being attempted.
            resource: The resource being accessed.
            context: Additional context.

        Returns:
            Dictionary with explanation details.
        """
        input_data = self._build_input(user, action, resource, context)

        # Add explain parameter
        explain_url = f"{self._query_url}?explain=full"

        try:
            request_data = json.dumps(input_data).encode("utf-8")
            req = urllib.request.Request(
                explain_url,
                data=request_data,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))

        except Exception as e:
            return {
                "error": str(e),
                "input": input_data,
            }

    def get_decision_id(self, response: dict[str, Any]) -> str | None:
        """
        Extract the decision ID from an OPA response.

        Decision IDs are useful for auditing and debugging.

        Args:
            response: The OPA response.

        Returns:
            The decision ID if present.
        """
        return response.get("decision_id")
