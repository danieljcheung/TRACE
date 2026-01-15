from pydantic import BaseModel, EmailStr, Field, field_validator


class VerifySendRequest(BaseModel):
    email: EmailStr

    @field_validator('email')
    @classmethod
    def normalize(cls, v: str) -> str:
        return v.lower().strip()


class VerifyConfirmRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6)

    @field_validator('email')
    @classmethod
    def normalize(cls, v: str) -> str:
        return v.lower().strip()

    @field_validator('code')
    @classmethod
    def numeric_only(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError('Code must be numeric')
        return v


class ScanRequest(BaseModel):
    scan_token: str = Field(..., min_length=32, max_length=64)
    depth: int = Field(default=1, ge=1, le=3)
