import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")

SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-secret-key-change-in-prod-32bytes")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Database credentials (sourced from environment variables)
DB_USER = os.getenv("DB_USER", "vulntracker_app")
DB_PASSWORD = os.getenv("DB_PASSWORD", "Tr@ckerDev2024!")

# Internal service API key
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "sk-vt-dev-key")

NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")

# Allowed CORS origins
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000").split(",")
    if origin.strip()
]
