"""
Run script for AI Security Gateway
"""

import uvicorn
from src.main import app
from src.config.settings import settings

if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.ENVIRONMENT == "development",
        reload_excludes=["*.db*", "*.log", "*logs*", "*.pytest_cache*", "*__pycache__*"],
        log_level=settings.normalized_log_level().lower()
    )
