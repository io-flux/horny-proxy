from fastapi import FastAPI, HTTPException, Response, Depends, status, Request, Form
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse, FileResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import yaml
import requests
import secrets
import datetime
from datetime import timezone
import uvicorn
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import timedelta
import logging
from enum import Enum
import os
from pathlib import Path
import argparse
from threading import Lock
import warnings
from passlib.exc import PasslibSecurityWarning
import json
from jinja2 import Template
# ------------------------------------------------------------------
# Jinja2 helper (one global Environment – auto-escape HTML)
# ------------------------------------------------------------------
from jinja2 import Environment, FileSystemLoader, select_autoescape
TEMPLATES = Environment(
        loader=FileSystemLoader("static"),
        autoescape=select_autoescape(["html", "xml"])
).get_template               # we'll call TEMPLATES("file.html")

from typing import Optional

# Set up logging (will be reconfigured in main)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Track first-time visitors per share for INFO logging
visitor_log_set = set()
visitor_log_lock = Lock()

# Initialize FastAPI app
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Load configuration
try:
    with open("config.yaml", "r") as config_file:
        config = yaml.safe_load(config_file)
except Exception as e:
    logger.error(f"Failed to load config.yaml: {e}")
    raise

HORNY_HOST = config['horny']['host']
HORNY_PORT = config['horny']['port']
BASE_DOMAIN = config['horny']['base_domain']
STASH_SERVER = f"http://{config['stash']['server_ip']}:{config['stash']['port']}"
STASH_API_KEY = config['stash']['api_key']
DISCLAIMER = config.get('disclaimer', '')
ADMIN_USERNAME = config['horny']['admin_username']
ADMIN_PASSWORD = config['horny']['admin_password']
DEFAULT_RESOLUTION = config['horny'].get('default_resolution', 'MEDIUM')
SHARE_ID_LENGTH = config['horny'].get('share_id_length', 8)

# Directory for storing .m3u8 files
SHARES_DIR = Path("static/shares")
SHARES_DIR.mkdir(exist_ok=True)

# JWT settings
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

try:
    HASHED_ADMIN_PASSWORD = pwd_context.hash(ADMIN_PASSWORD)
    logger.info("Admin password hashed successfully")
except Exception as e:
    logger.error(f"Failed to hash admin password: {e}")
    raise

# SQLite database setup
DATABASE_URL = "sqlite:///shared_videos.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Resolution Enum
class Resolution(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

# Database model
class SharedVideo(Base):
    __tablename__ = "shared_videos"
    id = Column(Integer, primary_key=True, index=True)
    share_id = Column(String, unique=True, index=True)
    video_name = Column(String)
    stash_video_id = Column(Integer)
    expires_at = Column(DateTime(timezone=True))
    hits = Column(Integer, default=0)
    resolution = Column(String, default=DEFAULT_RESOLUTION)
    password_hash = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# Pydantic models
class ShareVideoRequest(BaseModel):
    video_name: str
    stash_video_id: int
    days_valid: int = 7
    resolution: Resolution = Field(default=Resolution[DEFAULT_RESOLUTION], description="Streaming resolution")
    password: str | None = None

class Token(BaseModel):
    access_token: str
    token_type: str

# JWT authentication
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username != ADMIN_USERNAME:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

# Generate unique share ID
def generate_share_id():
    return secrets.token_urlsafe(SHARE_ID_LENGTH)

# Generate static .m3u8 file
def generate_m3u8_file(share_id: str, stash_video_id: int, resolution: str):
    stash_url = f"{STASH_SERVER}/scene/{stash_video_id}/stream.m3u8?apikey={STASH_API_KEY}&resolution={resolution}"
    try:
        response = requests.get(stash_url)
        if response.status_code != 200:
            logger.error(f"Failed to fetch .m3u8 from Stash: status={response.status_code}, url={stash_url}")
            raise Exception(f"Failed to fetch .m3u8: status={response.status_code}")
        
        # Verify response is a valid .m3u8 playlist
        if not response.text.startswith("#EXTM3U"):
            logger.error(f"Invalid .m3u8 content from Stash: {response.text[:100]}")
            raise Exception("Invalid .m3u8 content")
        
        # Parse and rewrite .m3u8 playlist
        lines = response.text.splitlines()
        rewritten_lines = []
        for line in lines:
            if line.strip() and not line.startswith("#") and ".ts" in line:
                # Extract segment name (e.g., "0.ts") from any URL, ignoring query parameters
                segment = line.split("/")[-1].split("?")[0]
                rewritten_lines.append(f"/share/{share_id}/stream/{segment}")
            else:
                rewritten_lines.append(line)
        
        # Save rewritten .m3u8 file
        m3u8_path = SHARES_DIR / f"{share_id}.m3u8"
        with open(m3u8_path, "w") as f:
            f.write("\n".join(rewritten_lines) + "\n")
        logger.info(f"Generated .m3u8 file for share_id={share_id} at {m3u8_path}")
        return True
    except Exception as e:
        logger.error(f"Error generating .m3u8 file for share_id={share_id}: {e}")
        return False

# Fetch and cache thumbnail from Stash
def fetch_and_cache_thumbnail(share_id: str, stash_video_id: int):
    thumbnail_url = f"{STASH_SERVER}/scene/{stash_video_id}/screenshot?apikey={STASH_API_KEY}"
    thumbnail_path = SHARES_DIR / f"{share_id}.jpg"
    try:
        if not thumbnail_path.exists():
            response = requests.get(thumbnail_url)
            if response.status_code == 200:
                with open(thumbnail_path, "wb") as f:
                    f.write(response.content)
                logger.info(f"Cached thumbnail for share_id={share_id} at {thumbnail_path}")
            else:
                logger.error(f"Failed to fetch thumbnail for share_id={share_id}: status={response.status_code}")
                return None
        return f"/static/shares/{share_id}.jpg"
    except Exception as e:
        logger.error(f"Error fetching thumbnail for share_id={share_id}: {e}")
        return None

# Root endpoint for gallery of active, non-password-protected shares
@app.get("/", response_class=HTMLResponse)
async def gallery():
    db = SessionLocal()
    try:
        # Get current time for expiration check
        current_time = datetime.datetime.now(timezone.utc)
        # Query for active, non-password-protected shares
        videos = db.query(SharedVideo).filter(
            SharedVideo.expires_at > current_time,
            SharedVideo.password_hash == None
        ).all()
        
        # Read the gallery template
        with open("static/gallery.html") as f:
            html_template = Template(f.read())
        
        # Generate video cards for the gallery
        video_cards = []
        for video in videos:
            thumbnail_url = fetch_and_cache_thumbnail(video.share_id, video.stash_video_id)
            video_cards.append({
                "share_id": video.share_id,
                "video_name": video.video_name,
                "share_url": f"/share/{video.share_id}",
                "thumbnail_url": thumbnail_url if thumbnail_url else "/static/default_thumbnail.jpg"
            })
        
        # Determine logo path and srcset (prefer localized, fallback to static)
        if os.path.exists("static/localized/logo.png"):
            logo_path = "/static/localized/logo.png"
            srcset = "/static/localized/logo.png 1x"
            if os.path.exists("static/localized/logo@2x.png"):
                srcset += ", /static/localized/logo@2x.png 2x"
            if os.path.exists("static/localized/logo@3x.png"):
                srcset += ", /static/localized/logo@3x.png 3x"
        else:
            logo_path = "/static/logo.png"
            srcset = "/static/logo.png 1x"
            if os.path.exists("static/logo@2x.png"):
                srcset += ", /static/logo@2x.png 2x"
            if os.path.exists("static/logo@3x.png"):
                srcset += ", /static/logo@3x.png 3x"
        
        # Render the HTML with video data using jinja2
        html_content = html_template.render(
            logo_path=logo_path,
            srcset=srcset,
            disclaimer=DISCLAIMER,
            video_cards=video_cards
        )
        return HTMLResponse(content=html_content)
    except Exception as e:
        logger.error(f"Error displaying gallery: {e}")
        raise HTTPException(status_code=500, detail="Failed to display gallery")
    finally:
        db.close()

# Admin panel redirect
@app.get("/__admin", response_class=RedirectResponse)
async def admin_panel():
    return RedirectResponse(url="/static/admin.html")

# Login endpoint
@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    logger.debug(f"Login attempt: username={form_data.username}")
    try:
        if not form_data.username or not form_data.password:
            logger.warning("Missing username or password in login request")
            raise HTTPException(status_code=422, detail="Username and password are required")
        if form_data.username != ADMIN_USERNAME:
            logger.warning(f"Invalid username: {form_data.username}")
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        if not pwd_context.verify(form_data.password, HASHED_ADMIN_PASSWORD):
            logger.warning("Password verification failed")
            raise HTTPException(status_code=401, detail="Incorrect username or password")
        access_token = create_access_token(data={"sub": form_data.username})
        logger.info(f"Login successful for username={form_data.username}")
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException as http_exc:
        logger.warning(f"Login HTTP exception: {http_exc.detail}")
        raise http_exc
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Share a video
@app.post("/share")
async def share_video(request: ShareVideoRequest, current_user: str = Depends(get_current_user)):
    share_id = generate_share_id()
    expires_at = datetime.datetime.now(timezone.utc) + datetime.timedelta(days=request.days_valid)
    
    db = SessionLocal()
    try:
        password_hash = None
        if request.password:
            password_hash = pwd_context.hash(request.password)
        
        shared_video = SharedVideo(
            share_id=share_id,
            video_name=request.video_name,
            stash_video_id=request.stash_video_id,
            expires_at=expires_at,
            hits=0,
            resolution=request.resolution,
            password_hash=password_hash
        )
        db.add(shared_video)
        db.commit()
        
        # Generate static .m3u8 file
        if not generate_m3u8_file(share_id, request.stash_video_id, request.resolution):
            raise HTTPException(status_code=500, detail="Failed to generate .m3u8 file")
        
        logger.info(f"Video shared: share_id={share_id}, stash_video_id={request.stash_video_id}, resolution={request.resolution}")
        share_url = f"{BASE_DOMAIN}/share/{share_id}"
        return {"share_url": share_url}
    except Exception as e:
        logger.error(f"Error sharing video: {e}")
        raise HTTPException(status_code=500, detail="Failed to share video")
    finally:
        db.close()

# Edit a share
@app.put("/edit_share/{share_id}")
async def edit_share(share_id: str, request: ShareVideoRequest, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        video = db.query(SharedVideo).filter(SharedVideo.share_id == share_id).first()
        if not video:
            raise HTTPException(status_code=404, detail="Share link not found")
        video.video_name = request.video_name
        video.expires_at = datetime.datetime.now(timezone.utc) + datetime.timedelta(days=request.days_valid)
        video.resolution = request.resolution
        if request.password:
            video.password_hash = pwd_context.hash(request.password)
        else:
            video.password_hash = None
        db.commit()
        
        # Regenerate .m3u8 file
        if not generate_m3u8_file(share_id, request.stash_video_id, request.resolution):
            raise HTTPException(status_code=500, detail="Failed to regenerate .m3u8 file")
        
        logger.info(f"Share updated: share_id={share_id}")
        return {"message": "Share updated"}
    except Exception as e:
        logger.error(f"Error updating share: {e}")
        raise HTTPException(status_code=500, detail="Failed to update share")
    finally:
        db.close()

# Delete a share
@app.delete("/delete_share/{share_id}")
async def delete_share(share_id: str, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        video = db.query(SharedVideo).filter(SharedVideo.share_id == share_id).first()
        if not video:
            raise HTTPException(status_code=404, detail="Share link not found")
        db.delete(video)
        db.commit()
        
        # Delete .m3u8 file
        m3u8_path = SHARES_DIR / f"{share_id}.m3u8"
        if m3u8_path.exists():
            m3u8_path.unlink()
            logger.info(f"Deleted .m3u8 file for share_id={share_id}")
        
        logger.info(f"Share deleted: share_id={share_id}")
        return {"message": "Share deleted"}
    except Exception as e:
        logger.error(f"Error deleting share: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete share")
    finally:
        db.close()

# ------------------------------------------------------------------
#  /share/{share_id}  (single, Jinja2 only)
# ------------------------------------------------------------------
@app.get("/share/{share_id}", response_class=HTMLResponse, response_model=None)
async def share_page(share_id: str,
                     password_verified: bool = False,
                     request=None):
    db = SessionLocal()
    try:
        video = db.query(SharedVideo).filter_by(share_id=share_id).first()
        if not video:
            raise HTTPException(status_code=404,
                                detail="Share link not found")

        if request:                               # first-time visitor log
            ip = request.client.host
            with visitor_log_lock:
                if (ip, share_id) not in visitor_log_set:
                    logger.info(f"Visitor {ip} requested {share_id}")
                    visitor_log_set.add((ip, share_id))

        if video.expires_at.replace(tzinfo=timezone.utc) \
                < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403,
                                detail="Share link has expired")

        # password gate -------------------------------------------------
        if video.password_hash and not password_verified:
            html = TEMPLATES("password-prompt.html").render(
                    video_name=video.video_name,
                    share_id=share_id)
            return HTMLResponse(html)

        # count hit BEFORE showing page
        video.hits += 1
        db.commit()

        # logo / srcset -------------------------------------------------
        if os.path.exists("static/localized/logo.png"):
            logo_path = "/static/localized/logo.png"
            srcset = ", ".join(p for p in [
                "/static/localized/logo.png 1x",
                os.path.exists("static/localized/logo@2x.png")
                 and "/static/localized/logo@2x.png 2x",
                os.path.exists("static/localized/logo@3x.png")
                 and "/static/localized/logo@3x.png 3x"] if p)
        else:
            logo_path = "/static/logo.png"
            srcset = ", ".join(p for p in [
                "/static/logo.png 1x",
                os.path.exists("static/logo@2x.png")
                 and "/static/logo@2x.png 2x",
                os.path.exists("static/logo@3x.png")
                 and "/static/logo@3x.png 3x"] if p)

        html = TEMPLATES("video-player.html").render(
                video_name = video.video_name,
                share_id   = share_id,
                logo_path  = logo_path,
                srcset     = srcset,
                disclaimer = DISCLAIMER)
        return HTMLResponse(html)

    finally:
        db.close()

# ------------------------------------------------------------------
#  password verification – just redirect, no manual HTML
# ------------------------------------------------------------------
@app.post("/share/{share_id}/verify")
async def verify_password(share_id: str, password: str = Form(...)):
    db = SessionLocal()
    try:
        vid = db.query(SharedVideo).filter_by(share_id=share_id).first()
        if not vid or not vid.password_hash \
           or not pwd_context.verify(password, vid.password_hash):
            raise HTTPException(status_code=401,
                                detail="Incorrect password")
    finally:
        db.close()
    # success → 303 to player page with flag; share_page will skip prompt
    return RedirectResponse(f"/share/{share_id}?password_verified=true",
                            status_code=303)


# Serve static .m3u8 file
@app.get("/share/{share_id}/stream.m3u8")
async def serve_m3u8_file(share_id: str):
    db = SessionLocal()
    try:
        video = db.query(SharedVideo).filter(SharedVideo.share_id == share_id).first()
        if not video:
            raise HTTPException(status_code=404, detail="Share link not found")
        expires_at_aware = video.expires_at.replace(tzinfo=timezone.utc)
        if expires_at_aware < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Share link has expired")
        
        m3u8_path = SHARES_DIR / f"{share_id}.m3u8"
        if not m3u8_path.exists():
            logger.warning(f".m3u8 file not found for share_id={share_id}, attempting to regenerate")
            if not generate_m3u8_file(share_id, video.stash_video_id, video.resolution):
                logger.error(f"Failed to regenerate .m3u8 file for share_id={share_id}")
                raise HTTPException(status_code=500, detail="Failed to regenerate .m3u8 file")
        
        return FileResponse(
            m3u8_path,
            media_type="application/x-mpegURL",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "public, max-age=10"
            }
        )
    except Exception as e:
        logger.error(f"Error serving .m3u8 file: {e}")
        raise HTTPException(status_code=500, detail="Failed to serve .m3u8 file")
    finally:
        db.close()

# Proxy HLS segments (.ts files)
@app.get("/share/{share_id}/stream/{segment}", response_class=StreamingResponse)
async def proxy_hls_segment(share_id: str, segment: str, request: Request = None):
    db = SessionLocal()
    try:
        video = db.query(SharedVideo).filter(SharedVideo.share_id == share_id).first()
        if not video:
            # Do not log non-existent shares
            raise HTTPException(status_code=404, detail="Share link not found")
        # DEBUG log for each segment request
        if request is not None:
            visitor_ip = request.client.host
            logger.debug(f"{visitor_ip} requested segment {segment} for share_id={share_id}")
        expires_at_aware = video.expires_at.replace(tzinfo=timezone.utc)
        if expires_at_aware < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Share link has expired")
        
        # Construct Stash segment URL
        stash_url = f"{STASH_SERVER}/scene/{video.stash_video_id}/stream.m3u8/{segment}?apikey={STASH_API_KEY}&resolution={video.resolution}"
        response = requests.get(stash_url, stream=True)
        if response.status_code != 200:
            logger.error(f"Failed to fetch HLS segment from Stash: status={response.status_code}, url={stash_url}")
            raise HTTPException(status_code=500, detail="Failed to fetch HLS segment from Stash")
        
        logger.debug(f"Proxied .ts segment for share_id={share_id}, segment={segment}")
        def stream_content():
            for chunk in response.iter_content(chunk_size=2048*1024):
                if chunk:
                    yield chunk
        
        return StreamingResponse(
            stream_content(),
            media_type="video/mp2t",
            headers={
                "Content-Length": response.headers.get("Content-Length"),
                "Accept-Ranges": "bytes",
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "public, max-age=3600"
            }
        )
    except Exception as e:
        logger.error(f"Error proxying HLS segment: {e}")
        raise HTTPException(status_code=500, detail="Failed to proxy HLS segment")
    finally:
        db.close()

# Get video title from Stash
@app.get("/get_video_title/{stash_id}")
async def get_video_title(stash_id: int, current_user: str = Depends(get_current_user)):
    stash_graphql_url = f"{STASH_SERVER}/graphql"
    headers = {
        "ApiKey": STASH_API_KEY,
        "Content-Type": "application/json"
    }
    query = {
        "query": """
            query FindScene($id: ID!) {
                findScene(id: $id) {
                    title
                    files {
                        basename
                    }
                }
            }
        """,
        "variables": {"id": stash_id}
    }

    logger.debug(f"Querying Stash for title of scene ID: {stash_id}")
    try:
        response = requests.post(stash_graphql_url, json=query, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("errors"):
            logger.error(f"GraphQL error from Stash: {data['errors']}")
            raise HTTPException(status_code=500, detail="GraphQL error from Stash")

        scene_data = data.get("data", {}).get("findScene")
        if scene_data and scene_data.get("title"):
            logger.info(f"Found title for Stash ID {stash_id}: {scene_data['title']}")
            return {"title": scene_data["title"]}
        else:
            logger.warning(f"Scene not found or title missing for Stash ID: {stash_id}")
            raise HTTPException(status_code=404, detail="Scene not found in Stash")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to Stash GraphQL API: {e}")
        raise HTTPException(status_code=503, detail="Could not connect to Stash API")
    except Exception as e:
        logger.error(f"Error fetching video title for ID {stash_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error fetching video title")

# List shared videos
@app.get("/shared_videos")
async def shared_videos(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        videos = db.query(SharedVideo).all()
        logger.info(f"Retrieved {len(videos)} shared videos")
        result = []
        for v in videos:
            share_url = f"{BASE_DOMAIN}/share/{v.share_id}"
            result.append(
                {
                    "share_id": v.share_id,
                    "video_name": f"{v.video_name} ({v.resolution})",
                    "stash_video_id": v.stash_video_id,
                    "expires_at": v.expires_at,
                    "hits": v.hits,
                    "share_url": share_url,
                    "resolution": v.resolution,
                    "has_password": v.password_hash is not None
                }
            )
        return result
    except Exception as e:
        logger.error(f"Error listing shared videos: {e}")
        raise HTTPException(status_code=500, detail="Failed to list shared videos")
    finally:
        db.close()

# Run Uvicorn server
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Horny Proxy server.")
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    warnings.filterwarnings("ignore", category=PasslibSecurityWarning)
    uvicorn.run(app, host=HORNY_HOST, port=HORNY_PORT, access_log=False)
