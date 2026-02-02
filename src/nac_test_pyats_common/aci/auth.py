# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""APIC authentication module for Cisco ACI (Application Centric Infrastructure).

This module provides authentication functionality for Cisco APIC (Application Policy
Infrastructure Controller), which is the central management and policy enforcement
point for ACI fabric. The authentication mechanism uses REST API calls to obtain
session tokens that are valid for a limited time period.

The module implements a two-tier API design:
1. authenticate() - Low-level method that performs direct APIC authentication
2. get_token() - High-level method that leverages caching for efficient token reuse

This design ensures efficient token management by reusing valid tokens and only
re-authenticating when necessary, reducing unnecessary API calls to the APIC controller.

Note on Fork Safety:
    This module uses urllib instead of httpx for synchronous authentication requests.
    httpx is NOT fork-safe on macOS - creating httpx.Client after fork() causes
    silent crashes due to OpenSSL threading issues. urllib uses simpler primitives
    that work correctly after fork().
"""

from nac_test.pyats_core.common.auth_cache import (
    AuthCache,  # type: ignore[import-untyped]
)

# Default token lifetime for APIC authentication tokens in seconds
# APIC tokens are typically valid for 10 minutes (600 seconds) by default
APIC_TOKEN_LIFETIME_SECONDS: int = 600

# HTTP timeout for authentication request
AUTH_REQUEST_TIMEOUT_SECONDS: float = 30.0


class APICAuth:
    """APIC-specific authentication implementation with token caching.

    This class provides a two-tier API for APIC authentication:

    1. Low-level authenticate() method: Directly authenticates with APIC and returns
       a token along with its expiration time. This is typically used by the caching
       layer and not called directly by consumers.

    2. High-level get_token() method: Provides cached token management, automatically
       handling token renewal when expired. This is the primary method that consumers
       should use for obtaining APIC tokens.

    The two-tier design ensures efficient token reuse across multiple API calls while
    maintaining clean separation between authentication logic and caching concerns.
    """

    @staticmethod
    def authenticate(url: str, username: str, password: str) -> tuple[str, int]:
        """Perform direct APIC authentication and obtain a session token.

        This method performs a direct authentication request to the APIC controller
        using the provided credentials. It returns both the token and its lifetime
        for proper cache management.

        Note: On macOS, SSL operations in forked processes crash due to OpenSSL
        threading issues. This method uses subprocess with spawn context to perform
        authentication in a fresh process, avoiding the fork+SSL crash.

        Args:
            url: Base URL of the APIC controller (e.g., "https://apic.example.com").
                Should not include trailing slashes or API paths.
            username: APIC username for authentication. This should be a valid user
                configured in the APIC with appropriate permissions.
            password: Password for the specified APIC user account.

        Returns:
            A tuple containing:
                - token (str): The APIC session token that should be included in
                  subsequent API requests as a cookie (APIC-cookie).
                - expires_in (int): Token lifetime in seconds (typically 600 seconds).

        Raises:
            RuntimeError: If authentication subprocess fails.
            ValueError: If the APIC response contains malformed JSON or unexpected
                structure that cannot be properly parsed.

        Note:
            SSL verification is disabled to handle self-signed certificates commonly
            used in lab and development APIC deployments. In production environments,
            proper certificate validation should be enabled.
        """
        import json
        import os
        import shlex
        import stat
        import sys
        import tempfile

        # =============================================================================
        # macOS Fork Safety: os.system() + temp files - NOT subprocess.run()
        # =============================================================================
        # CRITICAL: On macOS, after PyATS forks child processes:
        #   - subprocess.run() crashes due to pipe creation issues after fork
        #   - os.popen() also crashes (uses pipes internally)
        #
        # The ONLY reliable approach is os.system() which uses the system() syscall
        # that doesn't create pipes. To exchange data, we use temp files:
        #   1. Write auth params to input temp file
        #   2. Script reads from input file, authenticates, writes to output file
        #   3. We read result from output temp file
        #
        # This is slower but 100% fork-safe on macOS.
        # =============================================================================

        # Create temp files for input/output (avoid pipes)
        auth_params = {
            "url": url,
            "username": username,
            "password": password,
            "timeout": AUTH_REQUEST_TIMEOUT_SECONDS,
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix="_auth_in.json", delete=False
        ) as f_in:
            json.dump(auth_params, f_in)
            input_path = f_in.name
        # Restrict permissions since file contains credentials
        os.chmod(input_path, stat.S_IRUSR | stat.S_IWUSR)

        # Use NamedTemporaryFile instead of deprecated mktemp() to avoid race conditions
        with tempfile.NamedTemporaryFile(
            mode="w", suffix="_auth_out.json", delete=False
        ) as f_out:
            output_path = f_out.name
        # Restrict permissions for output file (will contain token)
        os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)

        # Auth script that reads/writes via temp files (no pipes)
        auth_script = f'''
import json
import ssl
import urllib.request

# Read auth params from input file
with open("{input_path}") as f:
    params = json.load(f)

url = params["url"]
username = params["username"]
password = params["password"]
timeout = params["timeout"]

try:
    # Create SSL context with verification disabled
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Build JSON payload for APIC authentication
    payload = json.dumps({{
        "aaaUser": {{
            "attributes": {{
                "name": username,
                "pwd": password
            }}
        }}
    }}).encode("utf-8")

    # Create request with proper headers
    request = urllib.request.Request(
        f"{{url}}/api/aaaLogin.json",
        data=payload,
        headers={{"Content-Type": "application/json"}},
        method="POST"
    )

    # Create HTTPS handler with SSL context
    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
    opener = urllib.request.build_opener(https_handler)

    # Execute authentication request
    response = opener.open(request, timeout=timeout)
    response_body = response.read().decode("utf-8")
    response_data = json.loads(response_body)

    # Extract token from response
    token = response_data["imdata"][0]["aaaLogin"]["attributes"]["token"]
    result = {{"token": token}}

except urllib.error.HTTPError as e:
    error_body = e.read().decode("utf-8") if e.fp else ""
    result = {{
        "error": f"HTTP {{e.code}}: {{e.reason}}",
        "response": error_body[:500]
    }}
except (KeyError, IndexError) as e:
    result = {{
        "error": f"Unexpected response structure: {{str(e)}}",
        "response": response_body[:500] if "response_body" in dir() else ""
    }}
except Exception as e:
    result = {{"error": str(e)}}

# Write result to output file
with open("{output_path}", "w") as f:
    json.dump(result, f)
'''

        # Write the script to a temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f_script:
            f_script.write(auth_script)
            script_path = f_script.name

        try:
            # Run via os.system() - the ONLY fork-safe method on macOS
            # Use shlex.quote() to prevent shell injection
            if os.name == "nt":
                # Windows: use double quotes
                cmd = f'"{sys.executable}" "{script_path}"'
            else:
                # Unix/macOS: use shlex.quote() for proper escaping
                cmd = f"{shlex.quote(sys.executable)} {shlex.quote(script_path)}"
            returncode = os.system(cmd)

            # os.system() returns the exit status shifted on Unix
            if os.name == "nt":
                actual_returncode = returncode
            else:
                # On Unix, os.system() returns the result of waitpid() which encodes
                # the exit status. os.waitstatus_to_exitcode() (Python 3.9+) handles
                # all cases (normal exit, signal termination, etc.)
                if hasattr(os, "waitstatus_to_exitcode"):
                    actual_returncode = os.waitstatus_to_exitcode(returncode)
                elif os.WIFEXITED(returncode):
                    actual_returncode = os.WEXITSTATUS(returncode)
                else:
                    # Process was killed by signal or other abnormal termination
                    actual_returncode = -1

            if actual_returncode != 0:
                raise RuntimeError(
                    f"Auth subprocess failed with exit code {actual_returncode}"
                )

            # Read result from output file
            if not os.path.exists(output_path):
                raise RuntimeError("Authentication subprocess did not produce output")

            with open(output_path) as f:
                auth_data = json.load(f)

        finally:
            # Clean up temp files
            for path in [input_path, output_path, script_path]:
                try:
                    os.unlink(path)
                except (OSError, FileNotFoundError):
                    pass  # Best effort cleanup

        if "error" in auth_data:
            error_detail = auth_data.get("response", "")
            error_msg = auth_data["error"]
            if error_detail:
                error_msg = f"{error_msg}. Response: {error_detail}"
            raise RuntimeError(f"APIC authentication failed: {error_msg}")

        return auth_data["token"], APIC_TOKEN_LIFETIME_SECONDS

    @classmethod
    def get_token(cls, url: str, username: str, password: str) -> str:
        """Get APIC token with automatic caching and renewal.

        This is the primary method that consumers should use to obtain APIC tokens.
        It leverages the AuthCache to efficiently manage token lifecycle, reusing
        valid tokens and automatically renewing expired ones. This significantly
        reduces the number of authentication requests to the APIC controller.

        The method uses a cache key based on the controller type ("ACI"), URL,
        and username to ensure proper token isolation between different APIC
        instances and user accounts.

        Args:
            url: Base URL of the APIC controller (e.g., "https://apic.example.com").
                Should not include trailing slashes or API paths.
            username: APIC username for authentication. This should be a valid user
                configured in the APIC with appropriate permissions.
            password: Password for the specified APIC user account.

        Returns:
            A valid APIC session token that can be used in API requests.
            The token should be included as a cookie (APIC-cookie) in subsequent
            API calls to the APIC controller.

        Raises:
            httpx.HTTPStatusError: If the APIC returns a non-2xx status code during
                authentication, typically indicating invalid credentials (401) or
                server issues (5xx).
            httpx.RequestError: If the request fails due to network issues,
                connection timeouts, or other transport-level problems.
            ValueError: If the APIC response contains malformed or unexpected JSON
                structure that cannot be properly parsed.

        Examples:
            >>> # Get a token for APIC access
            >>> token = APICAuth.get_token(
            ...     url="https://apic.example.com",
            ...     username="admin",
            ...     password="password123"
            ... )
            >>> # Use the token in subsequent API calls
            >>> headers = {"Cookie": f"APIC-cookie={token}"}
        """
        # AuthCache.get_or_create_token returns str, but mypy can't verify this
        # because nac_test lacks py.typed marker. The return type is guaranteed
        # by AuthCache's implementation which uses extract_token=True mode.
        return AuthCache.get_or_create_token(  # type: ignore[no-any-return]
            controller_type="ACI",
            url=url,
            username=username,
            password=password,
            auth_func=cls.authenticate,
        )
