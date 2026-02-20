"""
API - Authentication
"""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from app.config import settings

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest):
    """Login et retour du JWT token"""
    # TODO: vérification en base de données
    # Pour le POC, on accepte admin@voc.local / admin
    if data.email == "admin@voc.local" and data.password == "admin":
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token = jwt.encode(
            {"sub": data.email, "role": "admin", "exp": expire},
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
        return TokenResponse(
            access_token=token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
    raise HTTPException(status_code=401, detail="Invalid credentials")


@router.get("/me")
async def get_current_user():
    return {"email": "admin@voc.local", "role": "admin", "name": "VOC Admin"}
