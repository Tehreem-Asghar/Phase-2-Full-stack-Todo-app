import logging
from dotenv import load_dotenv
import os
load_dotenv()
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from database import create_db_and_tables, engine # Import engine

# Routers
from routers import auth
from routers import tasks

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS configuration
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "https://phase-ii-todo-full-stack-web-applic.vercel.app",
    # In a production environment, you would add your frontend's production URL here
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api") # Prefix with /api
app.include_router(tasks.router, prefix="/api") # Prefix with /api

# Custom exception handler for HTTPException
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logger.error(f"HTTP Exception: {exc.status_code} - {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.on_event("startup")
async def on_startup():
    logger.info("Application starting up. Creating database tables if they don't exist.")
    create_db_and_tables()

@app.on_event("shutdown")
async def on_shutdown():
    logger.info("Application shutting down.")
    # In a real application, you might want to close the database engine here if needed
    # engine.dispose()


@app.get("/")
def root():
    return {"message": "Hello World"}