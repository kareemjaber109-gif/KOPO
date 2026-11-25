from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import UserAccount, get_db
from src.api.models import (
    AuthLoginRequest,
    AuthRegisterRequest,
    AuthResponse,
    AuthUserResponse,
)
from src.api.services.auth_service import (
    ADMIN_INVITE_CODE,
    ADMIN_ROLES,
    USER_ROLES,
    hash_password,
    issue_auth_token,
    validate_email_address,
    validate_password_strength,
    verify_auth_token,
    verify_password,
)

router = APIRouter()


def _serialize_user(user: UserAccount) -> AuthUserResponse:
    return AuthUserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.post("/auth/register", response_model=AuthResponse, status_code=201)
async def register_user(
    payload: AuthRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        email = validate_email_address(payload.email)
        validate_password_strength(payload.password, require_complexity=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    name = payload.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=400, detail="Full name must be at least 2 characters")

    if payload.confirm_password is not None and payload.confirm_password != payload.password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    existing = (
        await db.execute(select(UserAccount).where(UserAccount.email == email))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists. Please sign in with your password.",
        )

    if payload.portal == "admin":
        if (payload.invite_code or "").strip() != ADMIN_INVITE_CODE:
            raise HTTPException(
                status_code=403,
                detail="Invalid administrator invite code. Contact SOC Command to provision an admin.",
            )
        assigned_role = "admin"
    else:
        if payload.role not in USER_ROLES:
            raise HTTPException(
                status_code=403,
                detail="Admin clearance cannot be self-assigned on the User portal. Use Admin Portal.",
            )
        assigned_role = payload.role

    now = datetime.utcnow()
    user = UserAccount(
        name=name,
        email=email,
        password_hash=hash_password(payload.password),
        role=assigned_role,
        created_at=now,
        last_login_at=now,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    token = issue_auth_token(user.id, user.email, user.role, payload.portal)
    return AuthResponse(user=_serialize_user(user), token=token, portal=payload.portal)


@router.post("/auth/login", response_model=AuthResponse)
async def login_user(
    payload: AuthLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        email = validate_email_address(payload.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user = (
        await db.execute(select(UserAccount).where(UserAccount.email == email))
    ).scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="No account found for this email address. Check the email or create an account.",
        )

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Incorrect password. Access denied.",
        )

    is_admin = user.role in ADMIN_ROLES
    if payload.portal == "admin" and not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Access denied: This account has Operator clearance. Sign in via User Login (/login/user).",
        )
    if payload.portal == "user" and is_admin:
        raise HTTPException(
            status_code=403,
            detail="This is an Administrator account. Please sign in via the Admin Login portal (/login/admin).",
        )

    user.last_login_at = datetime.utcnow()
    await db.commit()
    await db.refresh(user)

    token = issue_auth_token(user.id, user.email, user.role, payload.portal)
    return AuthResponse(user=_serialize_user(user), token=token, portal=payload.portal)


@router.get("/auth/me", response_model=AuthUserResponse)
async def current_user(
    authorization: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = verify_auth_token(token)
        user_id = int(payload["sub"])
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    user = (
        await db.execute(select(UserAccount).where(UserAccount.id == user_id))
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    return _serialize_user(user)
