from fastapi import FastAPI, HTTPException, Response, Depends, status, Request, Form
from fastapi.responses import StreamingResponse, HTMLResponse, RedirectResponse, FileResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
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
from urllib.parse import quote_plus, unquote_plus
import random
# ------------------------------------------------------------------
# Jinja2 helper (one global Environment – auto-escape HTML)
# ------------------------------------------------------------------
from jinja2 import Environment, FileSystemLoader, select_autoescape
JINJA_ENV = Environment(
        loader=FileSystemLoader("static"),
        autoescape=select_autoescape(["html", "xml"])
)
JINJA_ENV.filters['urlencode'] = quote_plus
TEMPLATES = JINJA_ENV.get_template               # we'll call TEMPLATES("file.html")

from typing import Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl

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

# Make sure LIMIT_TO_TAG is defined globally after config is loaded
LIMIT_TO_TAG = config['stash'].get('limit_to_tag', None)

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
SITE_NAME = config.get('site_name', 'Horny Proxy')  # Add site_name with fallback
SITE_MOTTO = config.get('site_motto', '')  # Add site_motto with empty default
SOCIAL_LINKS = config.get('social_links', [])  # Add social_links with empty list default

# SMTP settings for contact form
CONTACT_FORM_CONFIG = config.get('contact_form', {})
SMTP_MAILTO = CONTACT_FORM_CONFIG.get('mailto', '')
SMTP_HOST = CONTACT_FORM_CONFIG.get('host', '')
SMTP_PORT = CONTACT_FORM_CONFIG.get('port', 465)
SMTP_USER = CONTACT_FORM_CONFIG.get('user', '')
SMTP_PASS = CONTACT_FORM_CONFIG.get('pass', '')

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
    show_in_gallery = Column(Boolean, default=False)

class SharedTag(Base):
    __tablename__ = "shared_tags"
    id = Column(Integer, primary_key=True, index=True)
    share_id = Column(String, unique=True, index=True)
    tag_name = Column(String)
    stash_tag_id = Column(String)
    expires_at = Column(DateTime(timezone=True))
    hits = Column(Integer, default=0)
    resolution = Column(String, default=DEFAULT_RESOLUTION)
    password_hash = Column(String, nullable=True)
    show_in_gallery = Column(Boolean, default=False)

class TagVideoHit(Base):
    __tablename__ = "tag_video_hits"
    id = Column(Integer, primary_key=True, index=True)
    tag_share_id = Column(String, index=True)  # References SharedTag.share_id
    video_id = Column(Integer, index=True)      # Stash video ID
    hits = Column(Integer, default=0)

# Add this Pydantic model (add this after ShareVideoRequest)
class ShareTagRequest(BaseModel):
    tag_name: str
    tag_id: str
    days_valid: int = 7
    resolution: Resolution = Field(default=Resolution[DEFAULT_RESOLUTION], description="Streaming resolution")
    password: str | None = None
    show_in_gallery: bool = False
    custom_share_id: str | None = None

Base.metadata.create_all(bind=engine)

# Pydantic models
class ShareVideoRequest(BaseModel):
    video_name: str
    stash_video_id: int
    days_valid: int = 7
    resolution: Resolution = Field(default=Resolution[DEFAULT_RESOLUTION], description="Streaming resolution")
    password: str | None = None
    show_in_gallery: bool = False

class Token(BaseModel):
    access_token: str
    token_type: str

class DMCARequest(BaseModel):
    requester_name: str = Field(..., description="Requester Name or Company")
    requester_email: str = Field(..., description="Requester Email")
    requester_website: str = Field("", description="Requester Website")
    infringing_links: str = Field(..., description="Allegedly Infringing Links")

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

# Helper function to get or create tag video hit record
def get_or_create_tag_video_hit(db, tag_share_id: str, video_id: int):
    """Get or create a TagVideoHit record for tracking hits on individual videos within tag shares"""
    hit_record = db.query(TagVideoHit).filter(
        TagVideoHit.tag_share_id == tag_share_id,
        TagVideoHit.video_id == video_id
    ).first()
    
    if not hit_record:
        hit_record = TagVideoHit(
            tag_share_id=tag_share_id,
            video_id=video_id,
            hits=0
        )
        db.add(hit_record)
        db.commit()
    
    return hit_record

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

# Root endpoint for home page showing all available content
@app.get("/", response_class=HTMLResponse)
async def home(request: Request, sort: str = 'title'):
    db = SessionLocal()
    try:
        # Get current time for expiration check
        current_time = datetime.datetime.now(timezone.utc)
        
        # Query for active, non-password-protected video shares that are set to show in gallery
        individual_videos = db.query(SharedVideo).filter(
            SharedVideo.expires_at > current_time,
            SharedVideo.password_hash == None,
            SharedVideo.show_in_gallery == True
        ).all()
        
        # Query for active, non-password-protected tag shares that are set to show in gallery
        tag_shares = db.query(SharedTag).filter(
            SharedTag.expires_at > current_time,
            SharedTag.password_hash == None,
            SharedTag.show_in_gallery == True
        ).all()
        
        # Get the home template
        html_template = TEMPLATES("home.html")
        
        # ---
        # Data wrangling for combined gallery
        # ---
        
        # 1. Get all videos from gallery-enabled tag shares
        all_tag_videos = {}  # {video_id: video_info}
        tag_cards = []
        for tag in tag_shares:
            tag_videos, total_count = await get_videos_by_tag(tag.stash_tag_id)
            
            # Create tag cards for collections display
            if tag_videos:
                first_video = tag_videos[0]
                thumbnail_url = fetch_and_cache_tag_video_thumbnail(tag.share_id, int(first_video["id"]))
                tag_cards.append({
                    "share_id": tag.share_id,
                    "tag_name": tag.tag_name,
                    "share_url": f"/tag/{tag.share_id}",
                    "thumbnail_url": thumbnail_url if thumbnail_url else "/static/default_thumbnail.jpg",
                    "video_count": total_count,
                    "hits": tag.hits
                })
            
            # Add videos to master list (deduplicating by video_id)
            for video in tag_videos:
                video_id = int(video["id"])
                if video_id not in all_tag_videos:
                    all_tag_videos[video_id] = {
                        "video": video,
                        "tag_share_id": tag.share_id,
                        "tag_name": tag.tag_name,
                        "source": "tag"
                    }
        
        # 2. Get ratings for all individual videos in one go
        individual_video_ids = [v.stash_video_id for v in individual_videos]
        ratings = await get_ratings_for_videos(individual_video_ids)
        
        # 3. Create a combined list of all video cards
        all_video_cards = []
        
        # Add individual video shares
        for video in individual_videos:
            all_video_cards.append({
                "share_id": video.share_id,
                "video_name": video.video_name,
                "share_url": f"/share/{video.share_id}",
                "thumbnail_url": None, # Will be lazy loaded
                "lazy_thumbnail_url": f"/static/shares/{video.share_id}.jpg",
                "hits": video.hits,
                "stash_video_id": video.stash_video_id,
                "rating": ratings.get(video.stash_video_id, 0) or 0
            })
        
        # Add videos from tag shares (avoiding duplicates)
        individual_video_ids_set = set(individual_video_ids)
        for video_id, video_info in all_tag_videos.items():
            if video_id not in individual_video_ids_set:
                video_data = video_info["video"]
                tag_share_id = video_info["tag_share_id"]
                
                hit_record = db.query(TagVideoHit).filter(
                    TagVideoHit.tag_share_id == tag_share_id,
                    TagVideoHit.video_id == video_id
                ).first()
                
                all_video_cards.append({
                    "share_id": f"tag-{tag_share_id}-video-{video_id}",
                    "video_name": video_data["title"],
                    "share_url": f"/tag/{tag_share_id}/video/{video_id}",
                    "thumbnail_url": None, # Will be lazy loaded
                    "lazy_thumbnail_url": f"/tag/{tag_share_id}/thumbnail/{video_id}",
                    "hits": hit_record.hits if hit_record else 0,
                    "stash_video_id": video_id,
                    "rating": video_data.get("rating", 0) or 0
                })
        
        # 4. Sort the combined list
        if sort == 'hits':
            all_video_cards.sort(key=lambda v: v.get('hits', 0), reverse=True)
        elif sort == 'rating':
            all_video_cards.sort(key=lambda v: v.get('rating', 0), reverse=True)
        elif sort == 'random':
            random.shuffle(all_video_cards)
        else:  # Default to 'title'
            all_video_cards.sort(key=lambda v: v['video_name'])
        
        # Pre-fetch thumbnails for the first batch of sorted videos
        for i, card in enumerate(all_video_cards):
            if i < 24: # Number of thumbnails to preload
                if card['share_url'].startswith('/share/'):
                    card['thumbnail_url'] = fetch_and_cache_thumbnail(card['share_id'], card['stash_video_id'])
                else: # Tag video
                    parts = card['share_id'].split('-video-')
                    tag_share_id = parts[0][4:]
                    video_id = int(parts[1])
                    card['thumbnail_url'] = fetch_and_cache_tag_video_thumbnail(tag_share_id, video_id)
            else:
                break
        
        # Determine logo path and srcset (prefer localized, fallback to static)
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
        
        # Log final counts for debugging
        logger.info(f"Home page rendering: {len(tag_cards)} tag collections, {len(all_video_cards)} total videos")
        
        # Render the HTML with video data using jinja2
        html_content = html_template.render(
            logo_path=logo_path,
            srcset=srcset,
            disclaimer=DISCLAIMER,
            tag_cards=tag_cards,
            all_video_cards=all_video_cards, # Use the new combined and sorted list
            site_name=SITE_NAME,
            site_motto=SITE_MOTTO,
            social_links=SOCIAL_LINKS,
            base_domain=BASE_DOMAIN,
            sort=sort
        )
        return HTMLResponse(content=html_content)
    except Exception as e:
        logger.error(f"Error displaying gallery: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to display gallery")
    finally:
        db.close()

async def get_ratings_for_videos(video_ids: list[int]) -> dict[int, int]:
    """Get ratings for a list of video IDs from Stash."""
    if not video_ids:
        return {}

    stash_graphql_url = f"{STASH_SERVER}/graphql"
    headers = {"ApiKey": STASH_API_KEY, "Content-Type": "application/json"}
    
    query = {
        "operationName": "FindScenes",
        "variables": {"scene_ids": video_ids},
        "query": """
            query FindScenes($scene_ids: [Int!]) {
                findScenes(scene_ids: $scene_ids) {
                    scenes {
                        id
                        rating100
                    }
                }
            }
        """
    }

    try:
        response = requests.post(stash_graphql_url, json=query, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("errors"):
            logger.error(f"GraphQL error getting ratings: {data['errors']}")
            return {}

        scenes = data.get("data", {}).get("findScenes", {}).get("scenes", [])
        return {int(scene["id"]): scene.get("rating100") for scene in scenes if scene.get("rating100") is not None}
    except Exception as e:
        logger.error(f"Error fetching ratings for videos: {e}")
        return {}

async def find_tag_by_name(tag_name: str) -> dict | None:
    """Find a tag by name and return its ID and details"""
    stash_graphql_url = f"{STASH_SERVER}/graphql"
    headers = {
        "ApiKey": STASH_API_KEY,
        "Content-Type": "application/json"
    }
    
    query = {
        "operationName": "FindTags",
        "variables": {
            "filter": {
                "q": tag_name,
                "page": 1,
                "per_page": 1000,
                "sort": "scenes_count",
                "direction": "DESC"
            },
            "tag_filter": {}
        },
        "query": """
            query FindTags($filter: FindFilterType, $tag_filter: TagFilterType) {
                findTags(filter: $filter, tag_filter: $tag_filter) {
                    count
                    tags {
                        id
                        name
                        scene_count
                        __typename
                    }
                    __typename
                }
            }
        """
    }
    
    try:
        logger.debug(f"Searching for tag: {tag_name}")
        response = requests.post(stash_graphql_url, json=query, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data.get("errors"):
            logger.error(f"GraphQL error finding tag '{tag_name}': {data['errors']}")
            return None
        
        tags = data.get("data", {}).get("findTags", {}).get("tags", [])
        logger.debug(f"Found {len(tags)} tags matching '{tag_name}'")
        
        # Look for exact match first, then partial match
        for tag in tags:
            if tag["name"].lower() == tag_name.lower():
                logger.info(f"Exact match found for tag '{tag_name}': ID {tag['id']}")
                return tag
        
        # If no exact match, return first result if any
        if tags:
            logger.info(f"Partial match found for tag '{tag_name}': {tags[0]['name']} (ID {tags[0]['id']})")
            return tags[0]
        
        logger.warning(f"No tags found matching '{tag_name}'")
        return None
        
    except Exception as e:
        logger.error(f"Error finding tag '{tag_name}': {e}")
        return None

async def get_videos_by_tag(tag_id: str, page: int = 1, per_page: int = 1000, sort_by: str = 'date') -> tuple[list, int]:
    """Get videos that have a specific tag - returns (videos, total_count)"""
    stash_graphql_url = f"{STASH_SERVER}/graphql"
    headers = {
        "ApiKey": STASH_API_KEY,
        "Content-Type": "application/json"
    }
    # Compose tag filter
    tag_values = [tag_id]
    if LIMIT_TO_TAG:
        tag_values = [str(LIMIT_TO_TAG), str(tag_id)]
    query = {
        "operationName": "FindScenes",
        "variables": {
            "filter": {
                "q": "",
                "page": page,
                "per_page": per_page,
                "sort": sort_by,
                "direction": "DESC"
            },
            "scene_filter": {
                "tags": {
                    "value": tag_values,
                    "excludes": [],
                    "modifier": "INCLUDES_ALL",
                    "depth": 0 if LIMIT_TO_TAG else -1
                }
            }
        },
        "query": """
            query FindScenes($filter: FindFilterType, $scene_filter: SceneFilterType, $scene_ids: [Int!]) {
                findScenes(filter: $filter, scene_filter: $scene_filter, scene_ids: $scene_ids) {
                    count
                    scenes {
                        id
                        title
                        details
                        rating100
                        paths {
                            screenshot
                            preview
                            __typename
                        }
                        tags {
                            id
                            name
                            __typename
                        }
                        performers {
                            id
                            name
                            __typename
                        }
                        studio {
                            id
                            name
                            __typename
                        }
                        __typename
                    }
                    __typename
                }
            }
        """
    }
    
    try:
        logger.debug(f"Getting videos for tag ID: {tag_id}, page: {page}, per_page: {per_page}")
        response = requests.post(stash_graphql_url, json=query, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data.get("errors"):
            logger.error(f"GraphQL error getting videos for tag {tag_id}: {data['errors']}")
            return [], 0
        
        result = data.get("data", {}).get("findScenes", {})
        scenes = result.get("scenes", [])
        total_count = result.get("count", 0)
        
        # Transform the data to a simpler format
        videos = []
        for scene in scenes:
            video = {
                "id": scene["id"],
                "title": scene["title"],
                "details": scene.get("details", ""),
                "rating": scene.get("rating100"),
                "screenshot": scene["paths"]["screenshot"],
                "preview": scene["paths"]["preview"],
                "tags": [{"id": tag["id"], "name": tag["name"]} for tag in scene.get("tags", [])],
                "performers": [{"id": p["id"], "name": p["name"]} for p in scene.get("performers", [])],
                "studio": scene.get("studio", {}).get("name", "") if scene.get("studio") else ""
            }
            videos.append(video)
        
        logger.info(f"Found {len(videos)} videos (total: {total_count}) for tag {tag_id}")
        return videos, total_count
        
    except Exception as e:
        logger.error(f"Error getting videos for tag {tag_id}: {e}")
        return [], 0

async def get_all_videos_by_tag(tag_id: str) -> list:
    """Helper to get all videos for a tag, handling pagination."""
    all_videos = []
    page = 1
    per_page = 1000
    while True:
        videos, total_count = await get_videos_by_tag(tag_id, page=page, per_page=per_page)
        if not videos:
            break
        all_videos.extend(videos)
        if len(all_videos) >= total_count or total_count == 0:
            break
        page += 1
    logger.info(f"Fetched {len(all_videos)} total videos for tag_id {tag_id}")
    return all_videos

async def get_videos_by_tag_name(tag_name: str, page: int = 1, per_page: int = 1000) -> tuple[list, dict | None]:
    """Get videos by tag name - returns (videos, tag_info)"""
    logger.debug(f"Getting videos by tag name: {tag_name}")
    
    tag_info = await find_tag_by_name(tag_name)
    if not tag_info:
        logger.warning(f"Tag '{tag_name}' not found")
        return [], None
    
    videos, total_count = await get_videos_by_tag(tag_info["id"], page, per_page)
    logger.info(f"Retrieved {len(videos)} videos for tag '{tag_name}' (ID: {tag_info['id']})")
    return videos, tag_info


# Admin panel redirect
@app.get("/__admin", response_class=RedirectResponse)
async def admin_panel():
    return RedirectResponse(url="/static/admin.html")

# Get site configuration
@app.get("/site_config")
async def get_site_config():
    return {
        "site_name": SITE_NAME, 
        "site_motto": SITE_MOTTO, 
        "social_links": SOCIAL_LINKS,
        "base_domain": BASE_DOMAIN
    }

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
            password_hash=password_hash,
            show_in_gallery=request.show_in_gallery if hasattr(request, 'show_in_gallery') else False
        )
        db.add(shared_video)
        db.commit()
        
        # Generate static .m3u8 file
        if not generate_m3u8_file(share_id, request.stash_video_id, request.resolution):
            raise HTTPException(status_code=500, detail="Failed to generate .m3u8 file")
        
        logger.info(f"Video shared: share_id={share_id}, stash_video_id={request.stash_video_id}, resolution={request.resolution}")
        share_url = f"{BASE_DOMAIN}/share/{share_id}"
        if request.password:
            share_url += f"?pwd={request.password}"
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
        video.show_in_gallery = request.show_in_gallery if hasattr(request, 'show_in_gallery') else False
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
async def share_page(share_id: str, password_verified: bool = False, request: Request = None):
    db = SessionLocal()
    try:
        video = db.query(SharedVideo).filter_by(share_id=share_id).first()
        if not video:
            raise HTTPException(status_code=404,
                                detail="Share link not found")

        if request:  # first-time visitor log
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
            # Check if password is provided in URL
            query_params = request.query_params if request else {}
            url_password = query_params.get('pwd', '')
            if url_password and pwd_context.verify(url_password, video.password_hash):
                password_verified = True
            else:
                html = TEMPLATES("password-prompt.html").render(
                    video_name=video.video_name,
                    share_id=share_id,
                    url_password=url_password,
                    error_message=None
                )
                return HTMLResponse(html)

        # count hit BEFORE showing page
        video.hits += 1
        db.commit()
        
        # Get full video details from Stash
        video_details = await get_video_details(video.stash_video_id)

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
                disclaimer = DISCLAIMER,
                video_details = video_details,
                site_name = SITE_NAME,
                site_motto = SITE_MOTTO,
                social_links = SOCIAL_LINKS,
                base_domain = BASE_DOMAIN,
                hit_count = video.hits)
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
            # Render the password prompt again with an error message
            html = TEMPLATES("password-prompt.html").render(
                video_name=vid.video_name if vid else "",
                share_id=share_id,
                error_message="Incorrect password. Please try again."
            )
            return HTMLResponse(html, status_code=401)
    finally:
        db.close()
    # success → 303 to player page with flag; share_page will skip prompt
    return RedirectResponse(f"/share/{share_id}?password_verified=true",
                            status_code=303)



# Function to cache thumbnails for tag videos
def fetch_and_cache_tag_video_thumbnail(tag_share_id: str, video_id: int):
    thumbnail_url = f"{STASH_SERVER}/scene/{video_id}/screenshot?apikey={STASH_API_KEY}"
    thumbnail_path = SHARES_DIR / f"tag-{tag_share_id}-video-{video_id}.jpg"
    try:
        if not thumbnail_path.exists():
            response = requests.get(thumbnail_url)
            if response.status_code == 200:
                with open(thumbnail_path, "wb") as f:
                    f.write(response.content)
                logger.info(f"Cached thumbnail for tag video {tag_share_id}/{video_id} at {thumbnail_path}")
            else:
                logger.error(f"Failed to fetch thumbnail for tag video {tag_share_id}/{video_id}: status={response.status_code}")
                return None
        return f"/static/shares/tag-{tag_share_id}-video-{video_id}.jpg"
    except Exception as e:
        logger.error(f"Error fetching thumbnail for tag video {tag_share_id}/{video_id}: {e}")
        return None

# Tag share page endpoint
@app.get("/tag/{share_id}", response_class=HTMLResponse, response_model=None)
async def tag_share_page(share_id: str, password_verified: bool = False, request: Request = None, page: int = 1, sort: str = 'title'):
    db = SessionLocal()
    try:
        tag_share = db.query(SharedTag).filter_by(share_id=share_id).first()
        if not tag_share:
            raise HTTPException(status_code=404, detail="Tag share not found")

        if request:  # first-time visitor log
            ip = request.client.host
            with visitor_log_lock:
                if (ip, share_id) not in visitor_log_set:
                    logger.info(f"Visitor {ip} requested tag share {share_id}")
                    visitor_log_set.add((ip, share_id))

        if tag_share.expires_at.replace(tzinfo=timezone.utc) < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Tag share has expired")

        # password gate
        if tag_share.password_hash and not password_verified:
            query_params = request.query_params if request else {}
            url_password = query_params.get('pwd', '')
            if url_password and pwd_context.verify(url_password, tag_share.password_hash):
                password_verified = True
            else:
                html = TEMPLATES("password-prompt.html").render(
                    video_name=f"Tag: {tag_share.tag_name}",
                    share_id=share_id,
                    url_password=url_password
                )
                return HTMLResponse(html)

        # count hit BEFORE showing page
        tag_share.hits += 1
        db.commit()

        # Set pagination parameters
        per_page = 120  # Limit videos per page
        # Ensure page is at least 1
        if page < 1:
            page = 1

        # Get videos for this tag with pagination
        videos = []
        total_count = 0

        if sort == 'hits':
            # For hits, we need all videos, sort, then paginate manually
            all_videos_raw, _ = await get_all_videos_by_tag(tag_share.stash_tag_id)
            
            # Decorate with hit counts
            decorated_videos = []
            for video_raw in all_videos_raw:
                hit_record = db.query(TagVideoHit).filter(
                    TagVideoHit.tag_share_id == share_id,
                    TagVideoHit.video_id == int(video_raw["id"])
                ).first()
                video_raw['hits'] = hit_record.hits if hit_record else 0
                decorated_videos.append(video_raw)

            decorated_videos.sort(key=lambda v: v['hits'], reverse=True)
            
            total_count = len(decorated_videos)
            start = (page - 1) * per_page
            end = start + per_page
            videos = decorated_videos[start:end]
        
        elif sort == 'random':
            # Let Stash handle random sort, but we need to adjust total_count for pagination
            _, total_count = await get_videos_by_tag(tag_share.stash_tag_id, per_page=1) # get total count
            videos, _ = await get_videos_by_tag(tag_share.stash_tag_id, page=page, per_page=per_page, sort_by='random')
            
        else: # title, rating, date
            sort_map = {'title': 'title', 'rating': 'rating'}
            stash_sort = sort_map.get(sort, 'date')
            videos, total_count = await get_videos_by_tag(tag_share.stash_tag_id, page=page, per_page=per_page, sort_by=stash_sort)

        
        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page  # Ceiling division
        has_more_pages = page < total_pages
        
        # Transform videos for gallery display with proxied thumbnails
        video_cards = []
        for i, video in enumerate(videos):
            # Get hit count for this video
            hit_record = db.query(TagVideoHit).filter(
                TagVideoHit.tag_share_id == share_id,
                TagVideoHit.video_id == int(video["id"])
            ).first()
            hits = hit_record.hits if hit_record else 0
            
            # Skip thumbnail fetching after first 20 videos on a page to speed up initial load
            if i < 20:
                thumbnail_url = fetch_and_cache_tag_video_thumbnail(share_id, int(video["id"]))
            else:
                # For remaining videos, use a placeholder that will lazy load
                thumbnail_url = None
                
            video_cards.append({
                "share_id": f"tag-{share_id}-video-{video['id']}",
                "video_name": video["title"],
                "share_url": f"/tag/{share_id}/video/{video['id']}",
                "thumbnail_url": thumbnail_url if thumbnail_url else "/static/default_thumbnail.jpg",
                "lazy_thumbnail_url": f"/tag/{share_id}/thumbnail/{video['id']}" if not thumbnail_url else None,
                "hits": hits
            })

        # logo / srcset
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

        # Use the gallery template with pagination info
        html = TEMPLATES("gallery.html").render(
            logo_path=logo_path,
            srcset=srcset,
            disclaimer=DISCLAIMER,
            video_cards=video_cards,
            current_page=page,
            has_prev_page=page > 1,
            has_next_page=has_more_pages,
            prev_page_url=f"/tag/{share_id}?page={page-1}&sort={sort}" if page > 1 else None,
            next_page_url=f"/tag/{share_id}?page={page+1}&sort={sort}" if has_more_pages else None,
            tag_name=tag_share.tag_name,
            total_videos=len(video_cards),
            site_name=SITE_NAME,
            site_motto=SITE_MOTTO,
            social_links=SOCIAL_LINKS,
            base_domain=BASE_DOMAIN,
            sort=sort
        )
        return HTMLResponse(html)

    finally:
        db.close()

# Individual video within a tag share
@app.get("/tag/{share_id}/video/{video_id}", response_class=HTMLResponse, response_model=None)
async def tag_video_page(share_id: str, video_id: int, request: Request = None):
    db = SessionLocal()
    try:
        tag_share = db.query(SharedTag).filter_by(share_id=share_id).first()
        if not tag_share:
            raise HTTPException(status_code=404, detail="Tag share not found")

        if tag_share.expires_at.replace(tzinfo=timezone.utc) < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Tag share has expired")

        # Get video info from Stash
        videos, _ = await get_videos_by_tag(tag_share.stash_tag_id)
        video = next((v for v in videos if int(v["id"]) == video_id), None)
        
        if not video:
            raise HTTPException(status_code=404, detail="Video not found in this tag")
        
        # Track hits for this video
        hit_record = get_or_create_tag_video_hit(db, share_id, video_id)
        hit_record.hits += 1
        db.commit()

        # logo / srcset
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
            video_name=video["title"],
            share_id=f"tag-{share_id}-video-{video_id}",  # This maps to the m3u8 URL
            logo_path=logo_path,
            srcset=srcset,
            disclaimer=DISCLAIMER,
            video_details=video,
            site_name=SITE_NAME,
            site_motto=SITE_MOTTO,
            social_links=SOCIAL_LINKS,
            base_domain = BASE_DOMAIN,
            hit_count=hit_record.hits)
        return HTMLResponse(html)

    finally:
        db.close()

# Endpoint to serve thumbnails for tag videos on demand
@app.get("/tag/{share_id}/thumbnail/{video_id}")
async def get_tag_video_thumbnail(share_id: str, video_id: int):
    db = SessionLocal()
    try:
        tag_share = db.query(SharedTag).filter_by(share_id=share_id).first()
        if not tag_share:
            raise HTTPException(status_code=404, detail="Tag share not found")
        
        # Check expiration
        if tag_share.expires_at.replace(tzinfo=timezone.utc) < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Tag share has expired")
        
        # Fetch and cache the thumbnail
        thumbnail_url = fetch_and_cache_tag_video_thumbnail(share_id, video_id)
        if thumbnail_url:
            # Redirect to the cached thumbnail
            return RedirectResponse(url=thumbnail_url, status_code=302)
        else:
            # Redirect to default thumbnail if fetch failed
            return RedirectResponse(url="/static/default_thumbnail.jpg", status_code=302)
    finally:
        db.close()

# Add HLS endpoint for full video streaming on the site
@app.get("/share/{share_id}/stream.m3u8")
async def serve_m3u8_file(share_id: str):
    db = SessionLocal()
    try:
        # Check if it's a regular video share
        video = db.query(SharedVideo).filter(SharedVideo.share_id == share_id).first()
        if video:
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
        
        # Check if it's a tag video share (format: tag-{tag_share_id}-video-{video_id})
        if share_id.startswith("tag-") and "-video-" in share_id:
            parts = share_id.split("-video-")
            if len(parts) == 2:
                tag_share_id = parts[0][4:]  # Remove "tag-" prefix
                video_id = int(parts[1])
                
                tag_share = db.query(SharedTag).filter(SharedTag.share_id == tag_share_id).first()
                if tag_share:
                    expires_at_aware = tag_share.expires_at.replace(tzinfo=timezone.utc)
                    if expires_at_aware < datetime.datetime.now(timezone.utc):
                        raise HTTPException(status_code=403, detail="Tag share has expired")
                    
                    # Verify video belongs to this tag
                    videos, _ = await get_videos_by_tag(tag_share.stash_tag_id)
                    video_exists = any(int(v["id"]) == video_id for v in videos)
                    if not video_exists:
                        raise HTTPException(status_code=404, detail="Video not found in this tag")
                    
                    m3u8_path = SHARES_DIR / f"{share_id}.m3u8"
                    if not m3u8_path.exists():
                        logger.warning(f".m3u8 file not found for tag video {share_id}, attempting to generate")
                        if not generate_m3u8_file(share_id, video_id, tag_share.resolution):
                            logger.error(f"Failed to generate .m3u8 file for tag video {share_id}")
                            raise HTTPException(status_code=500, detail="Failed to generate .m3u8 file")
                    
                    return FileResponse(
                        m3u8_path,
                        media_type="application/x-mpegURL",
                        headers={
                            "Access-Control-Allow-Origin": "*",
                            "Cache-Control": "public, max-age=10"
                        }
                    )
        
        raise HTTPException(status_code=404, detail="Share link not found")
    except Exception as e:
        logger.error(f"Error serving .m3u8 file: {e}")
        raise HTTPException(status_code=500, detail="Failed to serve .m3u8 file")
    finally:
        db.close()

# Serve MP4 preview file instead of HLS stream for better compatibility with social platforms
@app.get("/share/{share_id}/stream.mp4")
async def serve_mp4_preview(share_id: str):
    db = SessionLocal()
    try:
        # Check if it's a regular video share
        video = db.query(SharedVideo).filter(SharedVideo.share_id == share_id).first()
        if video:
            expires_at_aware = video.expires_at.replace(tzinfo=timezone.utc)
            if expires_at_aware < datetime.datetime.now(timezone.utc):
                raise HTTPException(status_code=403, detail="Share link has expired")
            
            # Stream the preview from Stash
            preview_url = f"{STASH_SERVER}/scene/{video.stash_video_id}/preview?apikey={STASH_API_KEY}"
            response = requests.get(preview_url, stream=True)
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch preview from Stash: status={response.status_code}")
                raise HTTPException(status_code=500, detail="Failed to fetch preview")
            
            def stream_content():
                for chunk in response.iter_content(chunk_size=1024*1024):
                    if chunk:
                        yield chunk
            
            return StreamingResponse(
                stream_content(),
                media_type="video/mp4",
                headers={
                    "Accept-Ranges": "bytes",
                    "Cache-Control": "public, max-age=3600",
                    "Access-Control-Allow-Origin": "*"
                }
            )
        
        # Check if it's a tag video share (format: tag-{tag_share_id}-video-{video_id})
        if share_id.startswith("tag-") and "-video-" in share_id:
            parts = share_id.split("-video-")
            if len(parts) == 2:
                tag_share_id = parts[0][4:]  # Remove "tag-" prefix
                video_id = int(parts[1])
                
                tag_share = db.query(SharedTag).filter(SharedTag.share_id == tag_share_id).first()
                if tag_share:
                    expires_at_aware = tag_share.expires_at.replace(tzinfo=timezone.utc)
                    if expires_at_aware < datetime.datetime.now(timezone.utc):
                        raise HTTPException(status_code=403, detail="Tag share has expired")
                    
                    # Verify video belongs to this tag
                    videos, _ = await get_videos_by_tag(tag_share.stash_tag_id)
                    video_exists = any(int(v["id"]) == video_id for v in videos)
                    if not video_exists:
                        raise HTTPException(status_code=404, detail="Video not found in this tag")
                    
                    # Stream the preview from Stash
                    preview_url = f"{STASH_SERVER}/scene/{video_id}/preview?apikey={STASH_API_KEY}"
                    response = requests.get(preview_url, stream=True)
                    
                    if response.status_code != 200:
                        logger.error(f"Failed to fetch preview from Stash: status={response.status_code}")
                        raise HTTPException(status_code=500, detail="Failed to fetch preview")
                    
                    def stream_content():
                        for chunk in response.iter_content(chunk_size=1024*1024):
                            if chunk:
                                yield chunk
                    
                    return StreamingResponse(
                        stream_content(),
                        media_type="video/mp4",
                        headers={
                            "Accept-Ranges": "bytes",
                            "Cache-Control": "public, max-age=3600",
                            "Access-Control-Allow-Origin": "*"
                        }
                    )
        
        raise HTTPException(status_code=404, detail="Share link not found")
    except Exception as e:
        logger.error(f"Error serving MP4 preview: {e}")
        raise HTTPException(status_code=500, detail="Failed to serve MP4 preview")
    finally:
        db.close()

# Updated proxy_hls_segment to handle both regular and tag video shares
@app.get("/share/{share_id}/stream/{segment}", response_class=StreamingResponse)
async def proxy_hls_segment(share_id: str, segment: str, request: Request = None):
    db = SessionLocal()
    try:
        # Check if it's a regular video share
        video = db.query(SharedVideo).filter(SharedVideo.share_id == share_id).first()
        if video:
            if request is not None:
                visitor_ip = request.client.host
                logger.debug(f"{visitor_ip} requested segment {segment} for share_id={share_id}")
            expires_at_aware = video.expires_at.replace(tzinfo=timezone.utc)
            if expires_at_aware < datetime.datetime.now(timezone.utc):
                raise HTTPException(status_code=403, detail="Share link has expired")
            
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
        
        # Check if it's a tag video share
        if share_id.startswith("tag-") and "-video-" in share_id:
            parts = share_id.split("-video-")
            if len(parts) == 2:
                tag_share_id = parts[0][4:]  # Remove "tag-" prefix
                video_id = int(parts[1])
                
                tag_share = db.query(SharedTag).filter(SharedTag.share_id == tag_share_id).first()
                if tag_share:
                    if request is not None:
                        visitor_ip = request.client.host
                        logger.debug(f"{visitor_ip} requested segment {segment} for tag video {share_id}")
                    
                    expires_at_aware = tag_share.expires_at.replace(tzinfo=timezone.utc)
                    if expires_at_aware < datetime.datetime.now(timezone.utc):
                        raise HTTPException(status_code=403, detail="Tag share has expired")
                    
                    # Verify video belongs to this tag
                    videos, _ = await get_videos_by_tag(tag_share.stash_tag_id)
                    video_exists = any(int(v["id"]) == video_id for v in videos)
                    if not video_exists:
                        raise HTTPException(status_code=404, detail="Video not found in this tag")
                    
                    stash_url = f"{STASH_SERVER}/scene/{video_id}/stream.m3u8/{segment}?apikey={STASH_API_KEY}&resolution={tag_share.resolution}"
                    response = requests.get(stash_url, stream=True)
                    if response.status_code != 200:
                        logger.error(f"Failed to fetch HLS segment from Stash: status={response.status_code}, url={stash_url}")
                        raise HTTPException(status_code=500, detail="Failed to fetch HLS segment from Stash")
                    
                    logger.debug(f"Proxied .ts segment for tag video {share_id}, segment={segment}")
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
        
        raise HTTPException(status_code=404, detail="Share link not found")
    except Exception as e:
        logger.error(f"Error proxying HLS segment: {e}")
        raise HTTPException(status_code=500, detail="Failed to proxy HLS segment")
    finally:
        db.close()

# Proxy video preview for individual shares
@app.get("/share/{share_id}/preview")
async def proxy_video_preview(share_id: str, request: Request = None):
    db = SessionLocal()
    try:
        video = db.query(SharedVideo).filter(SharedVideo.share_id == share_id).first()
        if not video:
            raise HTTPException(status_code=404, detail="Share not found")
        
        # Check expiration
        if video.expires_at.replace(tzinfo=timezone.utc) < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Share has expired")
        
        # Stream the preview from Stash
        preview_url = f"{STASH_SERVER}/scene/{video.stash_video_id}/preview?apikey={STASH_API_KEY}"
        response = requests.get(preview_url, stream=True)
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch preview from Stash: status={response.status_code}")
            raise HTTPException(status_code=500, detail="Failed to fetch preview")
        
        def stream_content():
            for chunk in response.iter_content(chunk_size=1024*1024):
                if chunk:
                    yield chunk
        
        return StreamingResponse(
            stream_content(),
            media_type="video/mp4",
            headers={
                "Accept-Ranges": "bytes",
                "Cache-Control": "public, max-age=3600"
            }
        )
    finally:
        db.close()

# Proxy video preview for tag shares
@app.get("/tag/{share_id}/video/{video_id}/preview")
async def proxy_tag_video_preview(share_id: str, video_id: int, request: Request = None):
    db = SessionLocal()
    try:
        tag_share = db.query(SharedTag).filter(SharedTag.share_id == share_id).first()
        if not tag_share:
            raise HTTPException(status_code=404, detail="Tag share not found")
        
        # Check expiration
        if tag_share.expires_at.replace(tzinfo=timezone.utc) < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Tag share has expired")
        
        # Verify video belongs to this tag
        videos, _ = await get_videos_by_tag(tag_share.stash_tag_id)
        video_exists = any(int(v["id"]) == video_id for v in videos)
        if not video_exists:
            raise HTTPException(status_code=404, detail="Video not found in this tag")
        
        # Stream the preview from Stash
        preview_url = f"{STASH_SERVER}/scene/{video_id}/preview?apikey={STASH_API_KEY}"
        response = requests.get(preview_url, stream=True)
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch preview from Stash: status={response.status_code}")
            raise HTTPException(status_code=500, detail="Failed to fetch preview")
        
        def stream_content():
            for chunk in response.iter_content(chunk_size=1024*1024):
                if chunk:
                    yield chunk
        
        return StreamingResponse(
            stream_content(),
            media_type="video/mp4",
            headers={
                "Accept-Ranges": "bytes",
                "Cache-Control": "public, max-age=3600"
            }
        )
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
                    "has_password": v.password_hash is not None,
                    "show_in_gallery": v.show_in_gallery,
                    "password": v.password_hash if v.password_hash is not None else None  # For admin only
                }
            )
        return result
    except Exception as e:
        logger.error(f"Error listing shared videos: {e}")
        raise HTTPException(status_code=500, detail="Failed to list shared videos")
    finally:
        db.close()

# Lookup tag endpoint
@app.get("/lookup_tag/{tag_name}")
async def lookup_tag(tag_name: str, current_user: str = Depends(get_current_user)):
    """Lookup a tag and return info about it"""
    tag_name = unquote_plus(tag_name)
    try:
        videos, tag_info = await get_videos_by_tag_name(tag_name)
        
        if not tag_info:
            raise HTTPException(status_code=404, detail=f"Tag '{tag_name}' not found")
        
        logger.info(f"Tag lookup successful: {tag_name} -> {tag_info['id']} ({len(videos)} videos)")
        return {
            "tag_info": tag_info,
            "video_count": len(videos)
        }
    except HTTPException:
        # Re-raise HTTPException as-is (don't convert to 500 error)
        raise
    except Exception as e:
        logger.error(f"Error looking up tag '{tag_name}': {e}")
        raise HTTPException(status_code=500, detail="Failed to lookup tag")

# Share a tag
@app.post("/share_tag")
async def share_tag(request: ShareTagRequest, current_user: str = Depends(get_current_user)):
    """Share all videos with a specific tag"""
    logger.info(f"Tag share request: tag_name={request.tag_name}, tag_id={request.tag_id}")
    
    # Verify the tag exists and has videos using the provided tag_id
    try:
        videos, _ = await get_videos_by_tag(request.tag_id)
        
        if not videos:
            logger.warning(f"No videos found for tag ID {request.tag_id}")
            raise HTTPException(status_code=404, detail=f"No videos found for tag ID '{request.tag_id}'")
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except Exception as e:
        logger.error(f"Error getting videos for tag {request.tag_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify tag")
    
    # Generate share ID based on request
    if request.custom_share_id:
        share_id = request.custom_share_id
        # Check if this share_id already exists
        db = SessionLocal()
        try:
            existing_video = db.query(SharedVideo).filter(SharedVideo.share_id == share_id).first()
            existing_tag = db.query(SharedTag).filter(SharedTag.share_id == share_id).first()
            if existing_video or existing_tag:
                raise HTTPException(status_code=400, detail=f"Share ID '{share_id}' already exists")
        finally:
            db.close()
    else:
        share_id = generate_share_id()
    
    expires_at = datetime.datetime.now(timezone.utc) + datetime.timedelta(days=request.days_valid)
    
    db = SessionLocal()
    try:
        password_hash = None
        if request.password:
            password_hash = pwd_context.hash(request.password)
        
        shared_tag = SharedTag(
            share_id=share_id,
            tag_name=request.tag_name,
            stash_tag_id=request.tag_id,
            expires_at=expires_at,
            hits=0,
            resolution=request.resolution,
            password_hash=password_hash,
            show_in_gallery=request.show_in_gallery
        )
        db.add(shared_tag)
        db.commit()
        
        logger.info(f"Tag shared: share_id={share_id}, tag_name={request.tag_name}, tag_id={request.tag_id}, video_count={len(videos)}")
        share_url = f"{BASE_DOMAIN}/tag/{share_id}"
        if request.password:
            share_url += f"?pwd={request.password}"
        
        return {
            "share_url": share_url,
            "tag_name": request.tag_name,
            "video_count": len(videos),
            "share_id": share_id
        }
    except HTTPException:
        # Re-raise HTTPException as-is  
        raise
    except Exception as e:
        logger.error(f"Error sharing tag: {e}")
        raise HTTPException(status_code=500, detail="Failed to share tag")
    finally:
        db.close()

# List shared tags
@app.get("/shared_tags")
async def shared_tags(current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        tags = db.query(SharedTag).all()
        logger.info(f"Retrieved {len(tags)} shared tags")
        result = []
        for t in tags:
            share_url = f"{BASE_DOMAIN}/tag/{t.share_id}"
            result.append({
                "share_id": t.share_id,
                "tag_name": t.tag_name,
                "expires_at": t.expires_at,
                "hits": t.hits,
                "share_url": share_url,
                "resolution": t.resolution,
                "has_password": t.password_hash is not None,
                "show_in_gallery": t.show_in_gallery
            })
        return result
    except Exception as e:
        logger.error(f"Error listing shared tags: {e}")
        raise HTTPException(status_code=500, detail="Failed to list shared tags")
    finally:
        db.close()

# Delete a tag share
@app.delete("/delete_tag_share/{share_id}")
async def delete_tag_share(share_id: str, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        tag = db.query(SharedTag).filter(SharedTag.share_id == share_id).first()
        if not tag:
            raise HTTPException(status_code=404, detail="Tag share not found")
        
        db.delete(tag)
        db.commit()
        
        logger.info(f"Tag share deleted: share_id={share_id}")
        return {"message": "Tag share deleted"}
    except HTTPException:
        # Re-raise HTTPException as-is
        raise
    except Exception as e:
        logger.error(f"Error deleting tag share: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete tag share")
    finally:
        db.close()

# Edit a tag share
@app.put("/edit_tag_share/{share_id}")
async def edit_tag_share(share_id: str, request: ShareTagRequest, current_user: str = Depends(get_current_user)):
    db = SessionLocal()
    try:
        tag = db.query(SharedTag).filter(SharedTag.share_id == share_id).first()
        if not tag:
            raise HTTPException(status_code=404, detail="Tag share not found")
        
        tag.tag_name = request.tag_name
        tag.stash_tag_id = request.tag_id
        tag.expires_at = datetime.datetime.now(timezone.utc) + datetime.timedelta(days=request.days_valid)
        tag.resolution = request.resolution
        if request.password:
            tag.password_hash = pwd_context.hash(request.password)
        else:
            tag.password_hash = None
        tag.show_in_gallery = request.show_in_gallery
        db.commit()
        
        logger.info(f"Tag share updated: share_id={share_id}")
        return {"message": "Tag share updated"}
    except Exception as e:
        logger.error(f"Error updating tag share: {e}")
        raise HTTPException(status_code=500, detail="Failed to update tag share")
    finally:
        db.close()


# HLS endpoint for individual videos in tag shares
@app.get("/tag/{share_id}/video/{video_id}/stream.m3u8")
async def serve_tag_video_m3u8(share_id: str, video_id: int):
    db = SessionLocal()
    try:
        tag_share = db.query(SharedTag).filter(SharedTag.share_id == share_id).first()
        if not tag_share:
            raise HTTPException(status_code=404, detail="Tag share not found")
        
        expires_at_aware = tag_share.expires_at.replace(tzinfo=timezone.utc)
        if expires_at_aware < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Tag share has expired")
        
        # Check if this video actually belongs to this tag
        videos, _ = await get_videos_by_tag(tag_share.stash_tag_id)
        video_exists = any(int(v["id"]) == video_id for v in videos)
        if not video_exists:
            raise HTTPException(status_code=404, detail="Video not found in this tag")
        
        # Check for existing static m3u8 file first
        m3u8_path = SHARES_DIR / f"tag-{share_id}-video-{video_id}.m3u8"
        if not m3u8_path.exists():
            logger.warning(f".m3u8 file not found for tag video {share_id}/{video_id}, attempting to generate")
            if not generate_m3u8_file(f"tag-{share_id}-video-{video_id}", video_id, tag_share.resolution):
                logger.error(f"Failed to generate .m3u8 file for tag video {share_id}/{video_id}")
                raise HTTPException(status_code=500, detail="Failed to generate .m3u8 file")
        
        return FileResponse(
            m3u8_path,
            media_type="application/x-mpegURL",
            headers={
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "public, max-age=10"
            }
        )
    except Exception as e:
        logger.error(f"Error serving tag video .m3u8 file: {e}")
        raise HTTPException(status_code=500, detail="Failed to serve .m3u8 file")
    finally:
        db.close()

# MP4 preview endpoint for individual videos in tag shares
@app.get("/tag/{share_id}/video/{video_id}/stream.mp4")
async def serve_tag_video_mp4(share_id: str, video_id: int):
    db = SessionLocal()
    try:
        tag_share = db.query(SharedTag).filter(SharedTag.share_id == share_id).first()
        if not tag_share:
            raise HTTPException(status_code=404, detail="Tag share not found")
        
        expires_at_aware = tag_share.expires_at.replace(tzinfo=timezone.utc)
        if expires_at_aware < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Tag share has expired")
        
        # Check if this video actually belongs to this tag
        videos, _ = await get_videos_by_tag(tag_share.stash_tag_id)
        video_exists = any(int(v["id"]) == video_id for v in videos)
        if not video_exists:
            raise HTTPException(status_code=404, detail="Video not found in this tag")
        
        # Stream the preview from Stash
        preview_url = f"{STASH_SERVER}/scene/{video_id}/preview?apikey={STASH_API_KEY}"
        response = requests.get(preview_url, stream=True)
        
        if response.status_code != 200:
            logger.error(f"Failed to fetch preview from Stash: status={response.status_code}")
            raise HTTPException(status_code=500, detail="Failed to fetch preview")
        
        def stream_content():
            for chunk in response.iter_content(chunk_size=1024*1024):
                if chunk:
                    yield chunk
        
        return StreamingResponse(
            stream_content(),
            media_type="video/mp4",
            headers={
                "Accept-Ranges": "bytes",
                "Cache-Control": "public, max-age=3600",
                "Access-Control-Allow-Origin": "*"
            }
        )
    except Exception as e:
        logger.error(f"Error serving tag video MP4 preview: {e}")
        raise HTTPException(status_code=500, detail="Failed to serve MP4 preview")
    finally:
        db.close()

# Segment proxy for individual videos in tag shares
@app.get("/tag/{share_id}/video/{video_id}/stream/{segment}", response_class=StreamingResponse)
async def proxy_tag_video_segment(share_id: str, video_id: int, segment: str, request: Request = None):
    db = SessionLocal()
    try:
        tag_share = db.query(SharedTag).filter(SharedTag.share_id == share_id).first()
        if not tag_share:
            raise HTTPException(status_code=404, detail="Tag share not found")
        
        if request is not None:
            visitor_ip = request.client.host
            logger.debug(f"{visitor_ip} requested segment {segment} for tag video {share_id}/{video_id}")
        
        expires_at_aware = tag_share.expires_at.replace(tzinfo=timezone.utc)
        if expires_at_aware < datetime.datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Tag share has expired")
        
        # Check if this video actually belongs to this tag
        videos, _ = await get_videos_by_tag(tag_share.stash_tag_id)
        video_exists = any(int(v["id"]) == video_id for v in videos)
        if not video_exists:
            raise HTTPException(status_code=404, detail="Video not found in this tag")
        
        # Construct Stash segment URL
        stash_url = f"{STASH_SERVER}/scene/{video_id}/stream.m3u8/{segment}?apikey={STASH_API_KEY}&resolution={tag_share.resolution}"
        response = requests.get(stash_url, stream=True)
        if response.status_code != 200:
            logger.error(f"Failed to fetch HLS segment from Stash: status={response.status_code}, url={stash_url}")
            raise HTTPException(status_code=500, detail="Failed to fetch HLS segment from Stash")
        
        logger.debug(f"Proxied .ts segment for tag video {share_id}/{video_id}, segment={segment}")
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
        logger.error(f"Error proxying tag video HLS segment: {e}")
        raise HTTPException(status_code=500, detail="Failed to proxy HLS segment")
    finally:
        db.close()

# Get full video details from Stash
# DMCA takedown form page
@app.get("/dmca", response_class=HTMLResponse)
async def dmca_page():
    """Display the DMCA takedown request form"""
    try:
        # logo / srcset
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
        
        html = TEMPLATES("dmca-form.html").render(
            logo_path=logo_path,
            srcset=srcset,
            disclaimer=DISCLAIMER,
            site_name=SITE_NAME,
            site_motto=SITE_MOTTO,
            social_links=SOCIAL_LINKS,
            base_domain=BASE_DOMAIN
        )
        return HTMLResponse(html)
    except Exception as e:
        logger.error(f"Error displaying DMCA form: {e}")
        raise HTTPException(status_code=500, detail="Failed to display DMCA form")

# DMCA form submission handler
@app.post("/dmca/submit")
async def submit_dmca(request: DMCARequest):
    """Handle DMCA takedown form submission"""
    try:
        if not SMTP_MAILTO:
            logger.error("SMTP configuration missing - no mailto address configured")
            raise HTTPException(status_code=500, detail="Email configuration error")
        
        # Create email message
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = SMTP_MAILTO
        msg['Subject'] = f"DMCA Takedown Request from {request.requester_name}"
        
        # Build email body
        body = f"""
DMCA Takedown Request

Requester Name/Company: {request.requester_name}
Requester Email: {request.requester_email}
Requester Website: {request.requester_website}

Allegedly Infringing Links:
{request.infringing_links}

---
This request was submitted via the {SITE_NAME} DMCA form at {datetime.datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        try:
            context = ssl.create_default_context()
            if SMTP_PORT == 465:  # SMTPS (SSL from the start)
                server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context)
            elif SMTP_PORT == 587:  # STARTTLS
                server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
                server.ehlo() # Can be omitted
                server.starttls(context=context)
                server.ehlo() # Can be omitted
            else:
                # Fallback or error for unsupported port configurations for secure email
                logger.error(f"Unsupported SMTP port configuration for secure email: {SMTP_PORT}. Use 465 for SMTPS or 587 for STARTTLS.")
                raise HTTPException(status_code=500, detail="SMTP configuration error: Unsupported port for secure email.")

            if SMTP_USER and SMTP_PASS: # Only login if credentials are provided
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"DMCA takedown request sent from {request.requester_email}")
            return {"status": "success", "message": "Your DMCA takedown request has been submitted successfully."}
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication failed: {e}. Check SMTP_USER and SMTP_PASS.")
            raise HTTPException(status_code=500, detail="Email server authentication failed.")
        except smtplib.SMTPConnectError as e:
            logger.error(f"Failed to connect to SMTP server {SMTP_HOST}:{SMTP_PORT}: {e}")
            raise HTTPException(status_code=500, detail="Could not connect to email server.")
        except smtplib.SMTPServerDisconnected as e:
            logger.error(f"SMTP server disconnected: {e}")
            raise HTTPException(status_code=500, detail="Email server disconnected unexpectedly.")
        except ssl.SSLError as e:
            logger.error(f"SSL Error during SMTP communication: {e}. Check port ({SMTP_PORT}), SSL/TLS settings, and server certificates.")
            raise HTTPException(status_code=500, detail=f"SSL error with email server: {e}")
        except Exception as e:
            logger.error(f"Failed to send DMCA email: {e} (Host: {SMTP_HOST}, Port: {SMTP_PORT}, User: {SMTP_USER})")
            raise HTTPException(status_code=500, detail="Failed to send email due to an unexpected error.")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing DMCA submission: {e}")
        raise HTTPException(status_code=500, detail="Failed to process DMCA request")

async def get_video_details(stash_video_id: int) -> dict | None:
    """Get complete video details including performers, tags, studio, and URLs"""
    stash_graphql_url = f"{STASH_SERVER}/graphql"
    headers = {
        "ApiKey": STASH_API_KEY,
        "Content-Type": "application/json"
    }
    
    query = {
        "query": """
            query FindScene($id: ID!) {
                findScene(id: $id) {
                    id
                    title
                    details
                    date
                    rating100
                    organized
                    o_counter
                    urls
                    paths {
                        screenshot
                        preview
                        stream
                    }
                    file {
                        size
                        duration
                        video_codec
                        audio_codec
                        width
                        height
                        framerate
                        bitrate
                    }
                    files {
                        path
                        basename
                        size
                        duration
                        video_codec
                        audio_codec
                        width
                        height
                    }
                    performers {
                        name
                        gender
                        url
                        twitter
                        instagram
                        birthdate
                        ethnicity
                        country
                        hair_color
                        height_cm
                        measurements
                        fake_tits
                        tattoos
                        piercings
                        career_length
                        aliases
                    }
                    studio {
                        id
                        name
                        url
                    }
                    tags {
                        id
                        name
                        aliases
                        description
                    }
                    movies {
                        movie {
                            name
                            date
                        }
                    }
                    galleries {
                        title
                        url
                    }
                }
            }
        """,
        "variables": {"id": str(stash_video_id)}
    }
    
    try:
        logger.debug(f"Getting full details for scene ID: {stash_video_id}")
        response = requests.post(stash_graphql_url, json=query, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data.get("errors"):
            logger.error(f"GraphQL error getting scene details: {data['errors']}")
            return None
        
        scene = data.get("data", {}).get("findScene")
        if not scene:
            logger.warning(f"Scene {stash_video_id} not found")
            return None
        
        # Transform the data to a cleaner format
        video_details = {
            "id": scene["id"],
            "title": scene["title"],
            "details": scene.get("details", ""),
            "date": scene.get("date"),
            "rating": scene.get("rating100"),
            "urls": scene.get("urls", []),
            "duration": scene.get("file", {}).get("duration"),
            "resolution": f"{scene.get('file', {}).get('width')}x{scene.get('file', {}).get('height')}" if scene.get("file") else None,
            "files": scene.get("files", []),  # Include files array for fallback title
            "performers": [
                {
                    "name": p["name"],
                    "gender": p.get("gender"),
                    "url": p.get("url"),
                    "twitter": p.get("twitter"),
                    "instagram": p.get("instagram")
                } for p in scene.get("performers", [])
            ],
            "studio": {
                "name": scene.get("studio", {}).get("name"),
                "url": scene.get("studio", {}).get("url")
            } if scene.get("studio") else None,
            "tags": [
                {
                    "name": t["name"],
                    "description": t.get("description")
                } for t in scene.get("tags", [])
            ],
            "movies": [m["movie"]["name"] for m in scene.get("movies", []) if m.get("movie")],
            "galleries": scene.get("galleries", [])
        }
        
        logger.info(f"Retrieved full details for scene {stash_video_id}")
        return video_details
        
    except Exception as e:
        logger.error(f"Error getting scene details for ID {stash_video_id}: {e}")
        return None

@app.get("/gallery/tag/{tag_name}", response_class=HTMLResponse)
async def gallery_by_tag(tag_name: str, request: Request = None):
    tag_name = unquote_plus(tag_name)
    db = SessionLocal()
    try:
        # 1. Find tag_id from Stash
        tag_info = await find_tag_by_name(tag_name)
        if not tag_info:
            raise HTTPException(status_code=404, detail=f"Tag '{tag_name}' not found")
        
        tag_id = tag_info["id"]

        # 2. Find all videos with this tag from Stash
        target_videos_list = await get_all_videos_by_tag(tag_id)
        target_video_ids = {int(v['id']) for v in target_videos_list}

        # If no videos have this tag, we can show an empty gallery
        if not target_video_ids:
            logger.info(f"No videos found for tag '{tag_name}' in Stash.")

        # 3. Get all active shares from DB
        current_time = datetime.datetime.now(timezone.utc)
        individual_shares = db.query(SharedVideo).filter(SharedVideo.expires_at > current_time).all()
        tag_shares = db.query(SharedTag).filter(SharedTag.expires_at > current_time).all()

        video_cards = []
        processed_video_ids = set()

        # 4. Process individual shares
        logger.info(f"Processing {len(individual_shares)} individual shares for tag '{tag_name}' gallery...")
        for video in individual_shares:
            if video.stash_video_id in target_video_ids and video.stash_video_id not in processed_video_ids:
                logger.debug(f"Found match in individual share: video_id={video.stash_video_id}")
                thumbnail_url = fetch_and_cache_thumbnail(video.share_id, video.stash_video_id)
                video_cards.append({
                    "share_url": f"/share/{video.share_id}",
                    "video_name": video.video_name,
                    "thumbnail_url": thumbnail_url if thumbnail_url else "/static/default_thumbnail.jpg",
                    "hits": video.hits,
                    "lazy_thumbnail_url": None,
                })
                processed_video_ids.add(video.stash_video_id)

        # 5. Process tag shares
        logger.info(f"Processing {len(tag_shares)} tag shares for tag '{tag_name}' gallery...")
        for tag_share in tag_shares:
            # We need all videos from this tag share to check against our target tag
            shared_videos = await get_all_videos_by_tag(tag_share.stash_tag_id)
            for video in shared_videos:
                video_id = int(video['id'])
                if video_id in target_video_ids and video_id not in processed_video_ids:
                    logger.debug(f"Found match in tag share '{tag_share.tag_name}': video_id={video_id}")
                    # Use lazy loading for thumbnails here for performance
                    thumbnail_url = "/static/default_thumbnail.jpg"
                    lazy_thumbnail_url = f"/tag/{tag_share.share_id}/thumbnail/{video_id}"

                    hit_record = db.query(TagVideoHit).filter(TagVideoHit.tag_share_id == tag_share.share_id, TagVideoHit.video_id == video_id).first()
                    hits = hit_record.hits if hit_record else 0
                    
                    video_cards.append({
                        "share_url": f"/tag/{tag_share.share_id}/video/{video_id}",
                        "video_name": video["title"],
                        "thumbnail_url": thumbnail_url,
                        "lazy_thumbnail_url": lazy_thumbnail_url,
                        "hits": hits,
                    })
                    processed_video_ids.add(video_id)
        
        # Sort video cards by name
        video_cards.sort(key=lambda x: x['video_name'])
        
        # logo / srcset
        if os.path.exists("static/localized/logo.png"):
            logo_path = "/static/localized/logo.png"
            srcset = ", ".join(p for p in [
                "/static/localized/logo.png 1x",
                os.path.exists("static/localized/logo@2x.png") and "/static/localized/logo@2x.png 2x",
                os.path.exists("static/localized/logo@3x.png") and "/static/localized/logo@3x.png 3x"
            ] if p)
        else:
            logo_path = "/static/logo.png"
            srcset = ", ".join(p for p in [
                "/static/logo.png 1x",
                os.path.exists("static/logo@2x.png") and "/static/logo@2x.png 2x",
                os.path.exists("static/logo@3x.png") and "/static/logo@3x.png 3x"
            ] if p)

        logger.info(f"Rendering gallery for tag '{tag_name}' with {len(video_cards)} videos.")

        # Render gallery template
        html_content = TEMPLATES("gallery.html").render(
            logo_path=logo_path,
            srcset=srcset,
            disclaimer=DISCLAIMER,
            tag_name=tag_name,
            video_cards=video_cards,
            site_name=SITE_NAME,
            site_motto=SITE_MOTTO,
            social_links=SOCIAL_LINKS,
            base_domain=BASE_DOMAIN,
            current_page=None, # Disabling pagination for this view
            has_prev_page=False,
            has_next_page=False,
        )
        return HTMLResponse(content=html_content)

    except Exception as e:
        logger.error(f"Error displaying tag gallery for '{tag_name}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to display tag gallery")
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
