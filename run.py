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
        log_level=settings.normalized_log_level().lower()
    )
