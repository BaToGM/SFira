from fastapi import APIRouter, HTTPException, status

from app.core.security import create_access_token
from app.schemas import LoginRequest, TokenResponse, UserCreate
from app.services.store import store

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate) -> TokenResponse:
    try:
        user = store.create_user(payload)
    except ValueError as exc:
        detail = "Email already registered" if str(exc) == "email_taken" else "Only adults can register"
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc
    return TokenResponse(access_token=create_access_token(user.id), user=user)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest) -> TokenResponse:
    user = store.authenticate(payload.email, payload.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return TokenResponse(access_token=create_access_token(user.id), user=user)
