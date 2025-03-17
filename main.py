import random
import hashlib
from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.security import OAuth2PasswordBearer

templates = Jinja2Templates(directory="templates")

USER_DATABASE_URL = "sqlite:///./users.db"
ADMIN_DATABASE_URL = "sqlite:///./admins.db"
QUEUE_DATABASE_URL = "sqlite:///./queue.db"

SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXNzd29yZCI6InNlY3JldCJ9.dQw4w9WgXcQ"
ALGORITHM = "HS256"

Base = declarative_base()

user_engine = create_engine(USER_DATABASE_URL, connect_args={"check_same_thread": False})
admin_engine = create_engine(ADMIN_DATABASE_URL, connect_args={"check_same_thread": False})
queue_engine = create_engine(QUEUE_DATABASE_URL, connect_args={"check_same_thread": False})

UserSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=user_engine)
AdminSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=admin_engine)
QueueSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=queue_engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Queue(Base):
    __tablename__ = "queue"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)

class ActionLog(Base):
    __tablename__ = "action_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String)
    username = Column(String)
    action = Column(String)
    response = Column(String)

Base.metadata.create_all(bind=user_engine)
Base.metadata.create_all(bind=admin_engine)
Base.metadata.create_all(bind=queue_engine)

def get_user_db():
    db = UserSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_admin_db():
    db = AdminSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_queue_db():
    db = QueueSessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def authenticate_admin(db: Session, username: str, password: str):
    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin or not verify_password(password, admin.hashed_password):
        return False
    return admin

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def log_action(db: Session, username: str, action: str, response: str):
    log_entry = ActionLog(
        timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        username=username,
        action=action,
        response=response
    )
    db.add(log_entry)
    db.commit()

def generate_and_hash_code():
    code = str(random.randint(100, 999))
    hashed_code = hashlib.sha256((SECRET_KEY + code).encode('utf-8')).hexdigest()
    print(f"Numeric security code: {code}, Hashed code: {hashed_code}")
    return code, hashed_code

generated_code, hashed_code = generate_and_hash_code()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/healthcheck")
async def healthcheck():
    return {"status": "ok"}

@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    admin_key: str = Form(None),
    db: Session = Depends(get_user_db)
):
    if admin_key and hashlib.sha256((SECRET_KEY + admin_key).encode('utf-8')).hexdigest() == hashed_code:
        new_admin = Admin(username=username, hashed_password=get_password_hash(password))
        db.add(new_admin)
        db.commit()
        log_action(db, username, "register", "Admin registration successful")
        return RedirectResponse(url="/", status_code=303)

    if db.query(User).filter(User.username == username).first():
        log_action(db, username, "register", "Username already registered")
        error_message = "Username already registered"
        return templates.TemplateResponse("registration_error.html", {"request": request, "error_message": error_message})

    if db.query(User).filter(User.email == email).first():
        log_action(db, username, "register", "Email already registered")
        error_message = "Email already registered"
        return templates.TemplateResponse("registration_error.html", {"request": request, "error_message": error_message})

    new_user = User(username=username, email=email, hashed_password=get_password_hash(password))
    db.add(new_user)
    db.commit()
    log_action(db, username, "register", "Registration successful")

    return RedirectResponse(url="/", status_code=303)

@app.post("/token")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_user_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token({"sub": user.username})
    
    return JSONResponse(content={"access_token": access_token})

@app.get("/welcome", response_class=HTMLResponse)
async def welcome_page(request: Request, username: str = "Guest"):
    return templates.TemplateResponse("welcome.html", {"request": request, "username": username})

@app.get("/queue/position")
async def get_user_position(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_queue_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        queue_entry = db.query(Queue).filter(Queue.name == username).first()
        if not queue_entry:
            raise HTTPException(status_code=404, detail="User not found in queue")

        return {"id": queue_entry.id, "name": queue_entry.name}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/queue/add")
async def add_to_queue(
    request: Request,  
    db: Session = Depends(get_queue_db)
):
    try:
        authorization_header = request.headers.get("Authorization")
        if authorization_header is None:
            raise HTTPException(status_code=401, detail="Authorization header is missing")
        
        token_parts = authorization_header.split(" ")
        if len(token_parts) != 2 or token_parts[0] != "Bearer":
            raise HTTPException(status_code=400, detail="Malformed Authorization header")
        
        token = token_parts[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        new_queue_entry = Queue(name=username)
        db.add(new_queue_entry)
        db.commit()
        db.refresh(new_queue_entry)

        return {"id": new_queue_entry.id, "name": new_queue_entry.name}
    
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/queue/remove")
async def remove_from_queue(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_queue_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        queue_entry = db.query(Queue).filter(Queue.name == username).first()
        if not queue_entry:
            raise HTTPException(status_code=404, detail="User not found in queue")

        db.delete(queue_entry)
        db.commit()

        remaining_entries = db.query(Queue).filter(Queue.id > queue_entry.id).all()
        for entry in remaining_entries:
            entry.id -= 1
        db.commit()

        return {"message": "User removed", "id": queue_entry.id}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/admin/register")
async def register_admin(username: str = Form(...), password: str = Form(...), admin_key: str = Form(...), db: Session = Depends(get_admin_db)):
    
    print(admin_key)
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    if db.query(Admin).filter(Admin.username == username).first():
        raise HTTPException(status_code=400, detail="Admin username already registered")
    new_admin = Admin(username=username, hashed_password=get_password_hash(password))
    db.add(new_admin)
    db.commit()
    return {"message": "Admin registered successfully"}

@app.post("/admin/token") #Admin login
async def login_admin(form_data: OAuth2PasswordRequestForm = Depends(), admin_key: str = Form(...), db: Session = Depends(get_admin_db)):
    
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    admin = authenticate_admin(db, form_data.username, form_data.password)
    if not admin:
        raise HTTPException(status_code=401, detail="Incorrect admin username or password")

    access_token = create_access_token({"sub": admin.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/admin/queue/remove_first")
async def admin_remove_first(admin_key: str = Form(...), db: Session = Depends(get_queue_db)):
    
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    first_entry = db.query(Queue).filter(Queue.id == 1).first()
    if not first_entry:
        raise HTTPException(status_code=400, detail="Queue is empty")

    db.delete(first_entry)
    db.commit()

    remaining_entries = db.query(Queue).filter(Queue.id > first_entry.id).all()
    for entry in remaining_entries:
        entry.id -= 1
    db.commit()

    return {"message": "First entry removed", "queue": [entry.name for entry in remaining_entries]}

@app.get("/admin/queue/user/{queue_id}")
async def get_user_by_queue_id(queue_id: int, admin_key: str = Form(...), db: Session = Depends(get_queue_db)):
    
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    user_entry = db.query(Queue).filter(Queue.id == queue_id).first()
    if not user_entry:
        raise HTTPException(status_code=404, detail="User not found in queue")
    return {"id": user_entry.id, "name": user_entry.name}

@app.post("/admin/queue/remove")
async def remove_from_queue(token: str = Depends(oauth2_scheme), admin_key: str = Form(...), db: Session = Depends(get_queue_db)):
    
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        queue_entry = db.query(Queue).filter(Queue.name == username).first()
        if not queue_entry:
            raise HTTPException(status_code=404, detail="User not found in queue")

        db.delete(queue_entry)
        db.commit()

        remaining_entries = db.query(Queue).filter(Queue.id > queue_entry.id).all()
        for entry in remaining_entries:
            entry.id -= 1
        db.commit()

        return {"message": "User removed", "queue": [entry.name for entry in remaining_entries]}

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/admin/queue/clear")
async def clear_queue(admin_key: str = Form(...), db: Session = Depends(get_queue_db)):
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    db.query(Queue).delete()
    db.commit()
    
    return {"message": "Queue cleared successfully"}

@app.post("/admin/delete")
async def delete_admin(username: str = Form(...), admin_key: str = Form(...), db: Session = Depends(get_admin_db)):
    if hashed_code != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin key")
    if not admin_key:
        raise HTTPException(status_code=403, detail="Admin key is required")

    admin = db.query(Admin).filter(Admin.username == username).first()
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    db.delete(admin)
    db.commit()

    return {"message": f"Admin '{username}' deleted successfully"}

@app.get("/edit-account-home", response_class=HTMLResponse)
async def edit_account_home(request: Request):
    return templates.TemplateResponse("edit_account.html", {"request": request})

@app.get("/edit-account-username", response_class=HTMLResponse)
async def edit_account_username(request: Request):
    return templates.TemplateResponse("edit_account_username.html", {"request": request})

@app.get("/edit-account-password", response_class=HTMLResponse)
async def edit_account_password(request: Request):
    return templates.TemplateResponse("edit_account_password.html", {"request": request})

@app.get("/edit-account-email", response_class=HTMLResponse)
async def edit_account_email(request: Request):
    return templates.TemplateResponse("edit_account_email.html", {"request": request})

@app.post("/update-username")
async def update_username(
    new_username: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_user_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        old_username = payload.get("sub")
        
        if not old_username:
            raise HTTPException(status_code=401, detail="Invalid token")

        if new_username == old_username:
            raise HTTPException(status_code=406, detail="New username cannot be the same as the old one")

        if db.query(User).filter(User.username == new_username).first():
            raise HTTPException(status_code=400, detail="Username already taken")

        user = db.query(User).filter(User.username == old_username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.username = new_username
        db.commit()

        log_action(db, old_username, "update-username", f"Username changed to {new_username}")

        return {"message": f"successfully updated to {new_username}"}

    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    except HTTPException as e:
        if e.status_code == 406:
            raise e
        else:
            raise HTTPException(status_code=500, detail="Internal Server Error")
    
    except Exception as e:
        print(f"Error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/update-password")
async def update_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_user_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        if not verify_password(old_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Old password is incorrect")

        user.hashed_password = get_password_hash(new_password)
        db.commit()
        log_action(db, username, "update-password", "Password changed successfully")
        return {"message": "Password updated successfully"}

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/update-email")
async def update_email(
    new_email: str = Form(...),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_user_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        if db.query(User).filter(User.email == new_email).first():
            raise HTTPException(status_code=400, detail="Email already in use")

        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.email = new_email
        db.commit()
        log_action(db, username, "update-email", f"Email changed to {new_email}")
        return {"message": "Email updated successfully"}

    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")