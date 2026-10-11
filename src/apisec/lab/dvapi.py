"""Damn Vulnerable API (DvAPI) - Built-in mock API testbed for OWASP API Top 10."""

from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel


class LoginRequest(BaseModel):
    """User authentication payload."""

    username: str
    password: str


class ProxyRequest(BaseModel):
    """Outbound URL fetch proxy request."""

    url: str


def create_dvapi_app() -> FastAPI:
    """Instantiate and configure the intentionally vulnerable DvAPI lab application."""
    app = FastAPI(
        title="DvAPI - Damn Vulnerable API Lab",
        version="1.0.0",
        description="Target mock lab exposing deliberate OWASP API Top 10 security flaws.",
    )

    # In-memory user store
    users_db: dict[int, dict[str, Any]] = {
        1: {"id": 1, "username": "alice", "email": "alice@dvapi.local", "role": "user"},
        2: {"id": 2, "username": "bob", "email": "bob@dvapi.local", "role": "user"},
        99: {"id": 99, "username": "admin", "email": "admin@dvapi.local", "role": "admin"},
    }

    @app.post("/api/v1/auth/login", status_code=status.HTTP_200_OK, tags=["Authentication"])
    def login(req: LoginRequest) -> dict[str, Any]:
        """Authenticate and issue mock bearer access token."""
        if not req.username or not req.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )
        role = "admin" if req.username == "admin" else "user"
        return {
            "access_token": f"mock-token-{req.username}",
            "token_type": "bearer",  # nosec B105
            "role": role,
            "user_id": 99 if req.username == "admin" else 1,
        }

    @app.get("/api/v1/users/{id}", status_code=status.HTTP_200_OK, tags=["Users"])
    def get_user_profile(
        id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Fetch user profile.

        VULNERABILITY (API1: BOLA): Returns user data without verifying token tenant ownership.
        """
        user = users_db.get(id)
        if not user:
            # Return synthetic mock user profile so BOLA probe triggers
            return {"id": id, "username": f"user_{id}", "role": "user"}
        return user

    @app.get(
        "/api/v1/protected/data",
        status_code=status.HTTP_200_OK,
        tags=["Protected"],
        openapi_extra={"security": [{"bearerAuth": []}]},
    )
    def get_protected_data(
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Protected endpoint intended for authenticated requests.

        VULNERABILITY (API2: Broken Authentication): Does not validate token validity or presence.
        """
        # Flawed logic: grants access regardless of whether valid Bearer token is passed
        return {
            "secret": "dvapi-mock-secret-flag-12345",  # nosec B105
            "status": "authorized",
            "token_received": authorization or "none",
        }

    @app.put("/api/v1/users/{id}/profile", status_code=status.HTTP_200_OK, tags=["Users"])
    async def update_user_profile(
        id: int,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Update profile fields.

        VULNERABILITY (API3: Mass Assignment): Binds raw request JSON directly to user state.
        """
        body: dict[str, Any] = await request.json()
        target_user = users_db.get(id, {"id": id, "username": f"user_{id}", "role": "user"})
        updated = {**target_user, **body}
        users_db[id] = updated
        return updated

    @app.get("/api/v1/search", status_code=status.HTTP_200_OK, tags=["Search"])
    def search_query(
        q: str = "",
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Search items.

        VULNERABILITY (API4: Unrestricted Resource Consumption): No rate limit enforced.
        """
        return {
            "query": q,
            "results": [{"item_id": 1, "title": f"Result for {q}"}],
            "total": 1,
        }

    @app.delete(
        "/api/v1/admin/users/{id}",
        status_code=status.HTTP_200_OK,
        tags=["Administration"],
    )
    def admin_delete_user(
        id: int,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Admin endpoint to delete a user.

        VULNERABILITY (API5: BFLA): Accepts any Bearer token, fails to verify admin role.
        """
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Authorization required"
            )
        # Flawed check: any token is allowed, role check omitted!
        return {"status": "deleted", "deleted_user_id": id}

    @app.get("/api/v1/proxy/fetch", status_code=status.HTTP_200_OK, tags=["Proxy"])
    def proxy_fetch_query(url: str = "") -> dict[str, Any]:
        """Fetch remote resource URL via query param.

        VULNERABILITY (API6: SSRF): Fetches arbitrary internal addresses without validation.
        """
        url_lower = url.lower()
        if (
            "127.0.0.1" in url_lower
            or "localhost" in url_lower
            or "169.254.169.254" in url_lower
            or "internal" in url_lower
        ):
            return {
                "status": "success",
                "fetched_url": url,
                "meta-data": "ami-id: ami-091283719283 internal-cloud-metadata",
            }
        return {"status": "success", "fetched_url": url, "data": "public content"}

    @app.post("/api/v1/proxy/fetch", status_code=status.HTTP_200_OK, tags=["Proxy"])
    def proxy_fetch(req: ProxyRequest) -> dict[str, Any]:
        """Fetch remote resource URL.

        VULNERABILITY (API6: SSRF): Fetches arbitrary internal addresses without validation.
        """
        url_lower = req.url.lower()
        if (
            "127.0.0.1" in url_lower
            or "localhost" in url_lower
            or "169.254.169.254" in url_lower
            or "internal" in url_lower
        ):
            return {
                "status": "success",
                "fetched_url": req.url,
                "data": "internal-cloud-metadata-iam-token-flag",
            }
        return {"status": "success", "fetched_url": req.url, "data": "public content"}

    @app.get("/api/v1/public/ping", status_code=status.HTTP_200_OK, tags=["Public"])
    def public_ping(
        response: Response,
        origin: str | None = Header(default=None),
    ) -> dict[str, str]:
        """Public healthcheck ping.

        VULNERABILITY (API7: CORS Misconfiguration): Insecurely echoes any Origin with credentials.
        """
        if origin:
            response.headers["access-control-allow-origin"] = origin
            response.headers["access-control-allow-credentials"] = "true"
        return {"status": "ok", "message": "pong"}

    return app
