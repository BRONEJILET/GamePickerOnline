from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests
from deep_translator import GoogleTranslator
import sqlite3
from pydantic import BaseModel
import hashlib
import secrets
import re
# --- НОВЫЕ ИМПОРТЫ ДЛЯ GOOGLE LOGIN ---
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = FastAPI(title="GamePickerOnline API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RAWG_API_KEY = "9f57b2917ad04564baecb2015123510a" 
GOOGLE_CLIENT_ID = "663265296931-ch1t13bftrfliu1um89jqnnr15q5p41p.apps.googleusercontent.com"

def init_db():
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            token TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            slug TEXT,
            name TEXT,
            image_url TEXT,
            metacritic_score INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def get_user_by_token(token: str):
    if not token:
        raise HTTPException(status_code=401, detail="Необходима авторизация")
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE token = ?", (token,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Неверный или устаревший токен")
    return {"id": user[0], "username": user[1]}

class UserAuth(BaseModel):
    username: str
    password: str

class GoogleAuth(BaseModel):
    credential: str

class FavoriteGame(BaseModel):
    slug: str
    name: str
    image_url: str
    metacritic_score: int | None = None

# --- АВТОРИЗАЦИЯ ---
@app.post("/api/register")
def register(user: UserAuth):
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (user.username, hash_password(user.password)))
        conn.commit()
        return {"message": "Регистрация успешна! Теперь вы можете войти."}
    except sqlite3.IntegrityError:
        return {"error": "Пользователь с таким именем уже существует!"}
    finally:
        conn.close()

@app.post("/api/login")
def login(user: UserAuth):
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ? AND password_hash = ?", (user.username, hash_password(user.password)))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return {"error": "Неверный логин или пароль"}
    new_token = secrets.token_hex(16)
    cursor.execute("UPDATE users SET token = ? WHERE id = ?", (new_token, row[0]))
    conn.commit()
    conn.close()
    return {"message": "Вход выполнен", "token": new_token, "username": user.username}

# --- НОВАЯ РУЧКА: ВХОД ЧЕРЕЗ GOOGLE ---
@app.post("/api/google-login")
def google_login(data: GoogleAuth):
    try:
        # Проверяем токен через сервера Google
        idinfo = id_token.verify_oauth2_token(data.credential, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo['email']
        # Берем имя из Google, либо левую часть от email
        name = idinfo.get('name', email.split('@')[0]) 

        conn = sqlite3.connect("games.db")
        cursor = conn.cursor()
        
        # Проверяем, есть ли уже такой пользователь
        cursor.execute("SELECT id FROM users WHERE username = ?", (email,))
        row = cursor.fetchone()
        
        if not row:
            # Если нет - создаем нового (вместо пароля пишем заглушку)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (email, "GOOGLE_AUTH_NO_PASSWORD"))
            conn.commit()
            user_id = cursor.lastrowid
        else:
            user_id = row[0]

        # Выдаем нашу внутреннюю сессию
        new_token = secrets.token_hex(16)
        cursor.execute("UPDATE users SET token = ? WHERE id = ?", (new_token, user_id))
        conn.commit()
        conn.close()

        return {"message": "Вход через Google успешен!", "token": new_token, "username": name}

    except ValueError:
        return {"error": "Недействительный токен Google!"}

# --- ИЗБРАННОЕ ---
@app.get("/api/favorites")
def get_favorites(authorization: str = Header(None)):
    token = authorization.replace("Bearer ", "") if authorization else None
    user = get_user_by_token(token)
    conn = sqlite3.connect("games.db")
    cursor = conn.cursor()
    cursor.execute("SELECT slug, name, image_url, metacritic_score FROM favorites WHERE user_id = ?", (user["id"],))
    rows = cursor.fetchall()
    conn.close()
    return [{"slug": r[0], "name": r[1], "image_url": r[2], "metacritic_score": r[3]} for r in rows]

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
    cursor.execute("INSERT INTO favorites (user_id, slug, name, image_url, metacritic_score) VALUES (?, ?, ?, ?, ?)", (user["id"], game.slug, game.name, game.image_url, game.metacritic_score))
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

@app.get("/")
def read_root(): return {"message": "Сервер работает"}

@app.get("/api/top-games")
def get_top_games():
    url = f"https://api.rawg.io/api/games?key={RAWG_API_KEY}&ordering=-metacritic&page_size=12"
    return [{"slug": i.get("slug"), "name": i.get("name"), "image_url": i.get("background_image"), "metacritic_score": i.get("metacritic"), "release_date": i.get("released")} for i in requests.get(url).json().get("results", [])]

@app.get("/api/search")
def search_games(query: str):
    url = f"https://api.rawg.io/api/games?key={RAWG_API_KEY}&search={query}&page_size=12"
    res = [{"slug": i.get("slug"), "name": i.get("name"), "image_url": i.get("background_image"), "metacritic_score": i.get("metacritic"), "release_date": i.get("released")} for i in requests.get(url).json().get("results", [])]
    if not res: return {"error": "Ничего не найдено."}
    return res

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
                store_url = store_data.get("url", "")
                match = re.search(r'app/(\d+)', store_url)
                if match:
                    steam_id = match.group(1)
                    break
    except Exception as e:
        print(f"Ошибка получения магазинов: {e}")

    if steam_id:
        try:
            steam_url = f"https://store.steampowered.com/appreviews/{steam_id}?json=1&language=russian&filter=all&num_per_page=4"
            headers = {'User-Agent': 'Mozilla/5.0'}
            steam_res = requests.get(steam_url, headers=headers, timeout=5)
            if steam_res.status_code == 200:
                reviews_data = steam_res.json()
                for r in reviews_data.get("reviews", []):
                    clean_review = r.get("review", "").replace("\n", " ")
                    if len(clean_review) > 250:
                        clean_review = clean_review[:250] + "..."
                    steam_reviews.append({"voted_up": r.get("voted_up", True), "review": clean_review})
        except Exception as e:
            pass

    screenshots = []
    try:
        scr_url = f"https://api.rawg.io/api/games/{game_slug}/screenshots?key={RAWG_API_KEY}"
        scr_res = requests.get(scr_url, timeout=3).json()
        for item in scr_res.get("results", [])[:6]:
            screenshots.append(item.get("image"))
    except Exception as e:
        pass

    return {
        "name": raw_data.get("name"), "image_url": raw_data.get("background_image"), "metacritic_score": raw_data.get("metacritic"),
        "release_date": raw_data.get("released"), "platforms": [p["platform"]["name"] for p in raw_data.get("platforms", [])],
        "description": desc_ru, "website": raw_data.get("website"), "developers": [d["name"] for d in raw_data.get("developers", [])],
        "pc_minimum": pc_min, "pc_recommended": pc_rec,
        "steam_reviews": steam_reviews,
        "metacritic_url": raw_data.get("metacritic_url"),
        "screenshots": screenshots
    }