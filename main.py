from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests
from deep_translator import GoogleTranslator
import sqlite3
from pydantic import BaseModel
import hashlib
import secrets
import os
import re
import html
import time
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = FastAPI(title="GamePickerOnline API - RAWG Style")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RAWG_API_KEY = "9f57b2917ad04564baecb2015123510a" 
GOOGLE_CLIENT_ID = "67328762736-1pba95enhuh3c7jvlt38benvhhfruot2.apps.googleusercontent.com"

# Словарь для защиты от спама (Rate Limiting)
last_message_time = {}

def init_db():
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, token TEXT, avatar_url TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS favorites (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, slug TEXT, name TEXT, image_url TEXT, metacritic_score INTEGER, status TEXT DEFAULT 'В планах', FOREIGN KEY(user_id) REFERENCES users(id))")
    cursor.execute("CREATE TABLE IF NOT EXISTS threads (id INTEGER PRIMARY KEY AUTOINCREMENT, game_slug TEXT, title TEXT, author_id INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(author_id) REFERENCES users(id))")
    cursor.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, thread_id INTEGER, author_id INTEGER, content TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(thread_id) REFERENCES threads(id), FOREIGN KEY(author_id) REFERENCES users(id))")
    conn.commit()
    conn.close()

init_db()

def hash_password(password: str):
    salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + pwdhash.hex()

def verify_password(password: str, hashed_password: str):
    try:
        salt_hex, hash_hex = hashed_password.split(':')
        salt = bytes.fromhex(salt_hex)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return pwdhash.hex() == hash_hex
    except:
        return False

def get_user_by_token(token: str):
    if not token: raise HTTPException(status_code=401, detail="Необходима авторизация")
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, avatar_url FROM users WHERE token = ?", (token,))
    user = cursor.fetchone()
    conn.close()
    if not user: raise HTTPException(status_code=401, detail="Неверный или устаревший токен")
    return {"id": user[0], "username": user[1], "avatar_url": user[2]}

def sanitize_text(text: str):
    if not text: return ""
    return html.escape(text.strip())

class UserAuth(BaseModel): username: str; password: str
class GoogleAuth(BaseModel): credential: str
class FavoriteGame(BaseModel): slug: str; name: str; image_url: str; metacritic_score: int | None = None
class UpdateStatus(BaseModel): status: str
class NewThread(BaseModel): game_slug: str; title: str; message: str
class ReplyMessage(BaseModel): thread_id: int; content: str

@app.post("/api/register")
def register(user: UserAuth):
    if len(user.password) < 6: return {"error": "Пароль должен быть не менее 6 символов!"}
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    try:
        default_avatar = f"https://api.dicebear.com/7.x/bottts/svg?seed={user.username}"
        new_token = secrets.token_hex(16)
        cursor.execute("INSERT INTO users (username, password_hash, token, avatar_url) VALUES (?, ?, ?, ?)", (user.username, hash_password(user.password), new_token, default_avatar))
        conn.commit()
        return {"message": "Регистрация успешна!"}
    except sqlite3.IntegrityError: return {"error": "Пользователь с таким именем уже существует!"}
    finally: conn.close()

@app.post("/api/login")
def login(user: UserAuth):
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash, avatar_url, token FROM users WHERE username = ?", (user.username,))
    row = cursor.fetchone()
    if not row or not verify_password(user.password, row[1]):
        conn.close()
        return {"error": "Неверный логин или пароль"}
    existing_token = row[3]
    if not existing_token:
        new_token = secrets.token_hex(16)
        cursor.execute("UPDATE users SET token = ? WHERE id = ?", (new_token, row[0]))
        conn.commit()
    else: new_token = existing_token
    conn.close()
    return {"message": "Вход выполнен", "token": new_token, "username": user.username, "avatar_url": row[2]}

@app.post("/api/google-login")
def google_login(data: GoogleAuth):
    try:
        idinfo = id_token.verify_oauth2_token(data.credential, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo['email']
        name = idinfo.get('name', email.split('@')[0])
        avatar = idinfo.get('picture', f"https://api.dicebear.com/7.x/bottts/svg?seed={name}")
        conn = sqlite3.connect("games.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, token FROM users WHERE username = ?", (email,))
        row = cursor.fetchone()
        if not row:
            new_token = secrets.token_hex(16)
            cursor.execute("INSERT INTO users (username, password_hash, token, avatar_url) VALUES (?, ?, ?, ?)", (email, "GOOGLE_AUTH_NO_PASSWORD", new_token, avatar))
            conn.commit()
        else:
            user_id = row[0]
            existing_token = row[1]
            if existing_token: new_token = existing_token
            else: new_token = secrets.token_hex(16)
            cursor.execute("UPDATE users SET avatar_url = ?, token = ? WHERE id = ?", (avatar, new_token, user_id))
            conn.commit()
        conn.close()
        return {"message": "Вход через Google успешен!", "token": new_token, "username": name, "avatar_url": avatar}
    except ValueError: return {"error": "Недействительный токен Google!"}

@app.get("/api/user-info")
def get_user_info(authorization: str = Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_by_token(token)
    return {"username": user["username"], "avatar_url": user["avatar_url"]}

@app.get("/api/favorites")
def get_favorites(authorization: str = Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_by_token(token)
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("SELECT slug, name, image_url, metacritic_score, status FROM favorites WHERE user_id = ?", (user["id"],))
    rows = cursor.fetchall()
    conn.close()
    return [{"slug": r[0], "name": r[1], "image_url": r[2], "metacritic_score": r[3], "status": r[4]} for r in rows]

@app.post("/api/favorites")
def add_favorite(game: FavoriteGame, authorization: str = Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_by_token(token)
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM favorites WHERE user_id = ? AND slug = ?", (user["id"], game.slug))
    if cursor.fetchone():
        conn.close()
        return {"error": "Эта игра уже есть в вашем списке!"}
    cursor.execute("INSERT INTO favorites (user_id, slug, name, image_url, metacritic_score, status) VALUES (?, ?, ?, ?, ?, 'В планах')", (user["id"], game.slug, game.name, game.image_url, game.metacritic_score))
    conn.commit()
    conn.close()
    return {"message": "Игра успешно добавлена в избранное!"}

@app.delete("/api/favorites/{game_slug}")
def remove_favorite(game_slug: str, authorization: str = Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_by_token(token)
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM favorites WHERE user_id = ? AND slug = ?", (user["id"], game_slug))
    conn.commit()
    conn.close()
    return {"message": "Игра удалена из избранного."}

@app.patch("/api/favorites/{game_slug}/status")
def update_status(game_slug: str, data: UpdateStatus, authorization: str = Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_by_token(token)
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE favorites SET status = ? WHERE user_id = ? AND slug = ?", (data.status, user["id"], game_slug))
    conn.commit()
    conn.close()
    return {"message": "Статус обновлен!"}

@app.post("/api/forum/thread")
def create_thread(data: NewThread, authorization: str = Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_by_token(token)
    current_time = time.time()
    if user["id"] in last_message_time and current_time - last_message_time[user["id"]] < 10: return {"error": "Слишком частые запросы."}
    safe_title = sanitize_text(data.title)
    safe_message = sanitize_text(data.message)
    if len(safe_title) < 3 or len(safe_message) < 3: return {"error": "Слишком короткий текст."}
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO threads (game_slug, title, author_id) VALUES (?, ?, ?)", (data.game_slug, safe_title, user["id"]))
    thread_id = cursor.lastrowid
    cursor.execute("INSERT INTO messages (thread_id, author_id, content) VALUES (?, ?, ?)", (thread_id, user["id"], safe_message))
    conn.commit()
    conn.close()
    last_message_time[user["id"]] = current_time
    return {"message": "Тема успешно создана!", "thread_id": thread_id}

@app.get("/api/forum/{game_slug}")
def get_game_threads(game_slug: str):
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.id, t.title, u.username, t.created_at, 
               (SELECT COUNT(*) FROM messages WHERE thread_id = t.id) as msg_count
        FROM threads t JOIN users u ON t.author_id = u.id WHERE t.game_slug = ? ORDER BY t.created_at DESC
    """, (game_slug,))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1], "author": r[2], "created_at": r[3], "messages_count": r[4]} for r in rows]

@app.get("/api/forum/thread/{thread_id}")
def get_thread_messages(thread_id: int):
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT m.id, u.username, u.avatar_url, m.content, m.created_at
        FROM messages m JOIN users u ON m.author_id = u.id WHERE m.thread_id = ? ORDER BY m.created_at ASC
    """, (thread_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "author": r[1], "avatar_url": r[2], "content": r[3], "created_at": r[4]} for r in rows]

@app.post("/api/forum/message")
def add_message(data: ReplyMessage, authorization: str = Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_by_token(token)
    current_time = time.time()
    if user["id"] in last_message_time and current_time - last_message_time[user["id"]] < 5: return {"error": "Подождите пару секунд перед отправкой."}
    safe_content = sanitize_text(data.content)
    if len(safe_content) < 2: return {"error": "Слишком короткий текст."}
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (thread_id, author_id, content) VALUES (?, ?, ?)", (data.thread_id, user["id"], safe_content))
    conn.commit()
    conn.close()
    last_message_time[user["id"]] = current_time
    return {"message": "Ответ добавлен!"}

@app.get("/api/forum/recent")
def get_recent_threads():
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT t.id, t.game_slug, t.title, u.username, t.created_at,
               (SELECT COUNT(*) FROM messages WHERE thread_id = t.id) as msg_count
        FROM threads t JOIN users u ON t.author_id = u.id ORDER BY t.created_at DESC LIMIT 25
    """)
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "game_slug": r[1], "title": r[2], "author": r[3], "created_at": r[4], "messages_count": r[5]} for r in rows]

@app.get("/")
def read_root(): return {"message": "Сервер работает"}

@app.get("/api/top-games")
def get_top_games(page: int = 1, page_size: int = 15):
    # ИСПРАВЛЕНИЕ: Теперь сортируем по популярности (добавлениям) и показываем свежие хиты!
    url = f"https://api.rawg.io/api/games?key={RAWG_API_KEY}&dates=2023-01-01,2026-12-31&ordering=-added&page={page}&page_size={page_size}"
    try:
        data = requests.get(url).json()
        return [{"slug": i.get("slug"), "name": i.get("name"), "image_url": i.get("background_image"), "metacritic_score": i.get("metacritic"), "release_date": i.get("released")} for i in data.get("results", [])]
    except Exception: return []

@app.get("/api/search")
def search_games(query: str, page: int = 1):
    url = f"https://api.rawg.io/api/games?key={RAWG_API_KEY}&search={query}&page={page}&page_size=15"
    try:
        res = [{"slug": i.get("slug"), "name": i.get("name"), "image_url": i.get("background_image"), "metacritic_score": i.get("metacritic"), "release_date": i.get("released")} for i in requests.get(url).json().get("results", [])]
        if not res: return {"error": "Ничего не найдено."}
        return res
    except Exception: return {"error": "Ошибка при поиске."}

@app.get("/api/games/{game_slug}")
def get_game_info(game_slug: str):
    url = f"https://api.rawg.io/api/games/{game_slug}?key={RAWG_API_KEY}"
    response = requests.get(url)
    if response.status_code != 200: return {"error": "Игра не найдена."}
    raw_data = response.json()
    desc_clean = raw_data.get("description_raw", "Нет описания.").replace("#", "").strip()
    try: desc_ru = GoogleTranslator(source='auto', target='ru').translate(desc_clean[:4900])
    except: desc_ru = desc_clean 

    pc_min, pc_rec = "Нет данных", "Нет данных"
    for p in raw_data.get("platforms", []):
        if p.get("platform", {}).get("name") == "PC":
            reqs = p.get("requirements_en") or p.get("requirements_ru") or p.get("requirements") or {}
            pc_min, pc_rec = reqs.get("minimum", "Нет данных"), reqs.get("recommended", "Нет данных")
            break

    steam_reviews = []
    steam_id = None
    stores_url = f"https://api.rawg.io/api/games/{game_slug}/stores?key={RAWG_API_KEY}"
    try:
        stores_res = requests.get(stores_url, timeout=3).json()
        for store_data in stores_res.get("results", []):
            if store_data.get("store_id") == 1:
                match = re.search(r'app/(\d+)', store_data.get("url", ""))
                if match:
                    steam_id = match.group(1)
                    break
    except Exception: pass

    if steam_id:
        try:
            steam_url = f"https://store.steampowered.com/appreviews/{steam_id}?json=1&language=russian&filter=all&num_per_page=4"
            steam_res = requests.get(steam_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
            if steam_res.status_code == 200:
                for r in steam_res.json().get("reviews", []):
                    clean_review = r.get("review", "").replace("\n", " ")
                    if len(clean_review) > 250: clean_review = clean_review[:250] + "..."
                    steam_reviews.append({"voted_up": r.get("voted_up", True), "review": clean_review})
        except Exception: pass

    screenshots = []
    try:
        scr_url = f"https://api.rawg.io/api/games/{game_slug}/screenshots?key={RAWG_API_KEY}"
        for item in requests.get(scr_url, timeout=3).json().get("results", [])[:6]:
            screenshots.append(item.get("image"))
    except Exception: pass

    return {
        "name": raw_data.get("name"), "image_url": raw_data.get("background_image"), "metacritic_score": raw_data.get("metacritic"),
        "release_date": raw_data.get("released"), "platforms": [p["platform"]["name"] for p in raw_data.get("platforms", [])],
        "description": desc_ru, "website": raw_data.get("website"), "developers": [d["name"] for d in raw_data.get("developers", [])],
        "pc_minimum": pc_min, "pc_recommended": pc_rec, "steam_reviews": steam_reviews,
        "metacritic_url": raw_data.get("metacritic_url"), "screenshots": screenshots
    }
