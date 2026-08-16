"""
Task Manager API — built with FastAPI and SQLAlchemy.

Features:
    - User registration with bcrypt password hashing
    - Login that issues a signed JWT access token
    - Token-protected routes: every request must carry the token
    - Per-user data ownership: users only ever see their own tasks
    - Full CRUD for tasks, plus marking done and filtering by status

Run with:
    uvicorn main:app --reload

Interactive docs:
    http://127.0.0.1:8000/docs
"""

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from decouple import config
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from database import Session, Task, User

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────

# Read from .env so the key never reaches version control.
SECRET_KEY = config("SECRET_KEY")
ALGORITHM = "HS256"
TOKEN_LIFETIME_MINUTES = 30

# Pulls the token out of the Authorization header.
# tokenUrl only tells /docs where the login form lives.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI(title="Task Manager API")
session = Session()


# ─────────────────────────────────────────────
#  Request models
#  These define the shape of the JSON the client sends
# ─────────────────────────────────────────────

class UserReq(BaseModel):
    """Body for registration requests."""
    username: str
    password: str


class TaskReq(BaseModel):
    """Body for creating or updating a task."""
    title: str


# ─────────────────────────────────────────────
#  Authentication dependency
# ─────────────────────────────────────────────

def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Identify the caller from their token.

    Any route that declares Depends(get_current_user) runs this first.
    The user id comes from the signed token, never from the URL, so a
    caller cannot claim to be someone else.

    Raises 401 if the token is missing, forged, or expired.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload["user_id"]
    except Exception:
        # jwt raises several different errors; all of them mean the
        # same thing to the caller, so they collapse into one 401.
        raise HTTPException(status_code=401, detail="Invalid token")

    # The token may be valid but the account deleted since it was issued.
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# ─────────────────────────────────────────────
#  Authentication routes
#  These two are deliberately public — everything else is locked.
# ─────────────────────────────────────────────

@app.post("/register")
def register(data: UserReq):
    """Create a new account. Usernames must be unique."""
    existing = session.query(User).filter(
        User.username == data.username
    ).first()

    if existing:
        raise HTTPException(
            status_code=400,
            detail="This username is already taken",
        )

    # Hash before storing. gensalt() adds random data, so identical
    # passwords produce different hashes.
    hashed = bcrypt.hashpw(
        data.password.encode(),
        bcrypt.gensalt(),
    ).decode()

    new_user = User(username=data.username, password=hashed)
    session.add(new_user)
    session.commit()

    return {
        "message": "Registration successful",
        "user_id": new_user.id,
    }


@app.post("/login")
def login(data: OAuth2PasswordRequestForm = Depends()):
    """
    Verify credentials and issue an access token.

    Takes form data rather than JSON because that is what the OAuth2
    standard expects — it is also what makes the Authorize button in
    /docs work.
    """
    user = session.query(User).filter(
        User.username == data.username
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # checkpw re-hashes the supplied password and compares the hashes.
    # The original password is never recoverable from storage.
    is_correct = bcrypt.checkpw(
        data.password.encode(),
        user.password.encode(),
    )

    if not is_correct:
        raise HTTPException(status_code=401, detail="Wrong password")

    # The payload is readable by anyone holding the token, but the
    # signature makes it tamper-proof. exp limits the damage if it leaks.
    payload = {
        "user_id": user.id,
        "exp": datetime.now(timezone.utc) + timedelta(
            minutes=TOKEN_LIFETIME_MINUTES
        ),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": token, "token_type": "bearer"}


# ─────────────────────────────────────────────
#  Task routes
#  Every one of these requires a valid token.
#  Routes that take a task_id also check ownership, otherwise any
#  logged-in user could reach another user's tasks by guessing ids.
# ─────────────────────────────────────────────

@app.post("/tasks")
def add_task(data: TaskReq, user=Depends(get_current_user)):
    """Create a task owned by the caller."""
    # done defaults to False, so it is not set here.
    # The owner comes from the token, not from the request body.
    new_task = Task(title=data.title, user_id=user.id)
    session.add(new_task)
    session.commit()

    return {
        "message": f"Task '{data.title}' added successfully",
        "task_id": new_task.id,
    }


@app.get("/tasks")
def get_tasks(user=Depends(get_current_user)):
    """List every task belonging to the caller."""
    tasks = session.query(Task).filter(Task.user_id == user.id).all()
    return tasks


@app.get("/tasks/filter")
def filter_tasks(done: bool = None, user=Depends(get_current_user)):
    """List the caller's tasks, optionally narrowed by done status."""
    # Scope to the owner first, then narrow — never the other way round.
    query = session.query(Task).filter(Task.user_id == user.id)

    if done is not None:
        query = query.filter(Task.done == done)

    tasks = query.all()

    return [
        {"id": t.id, "title": t.title, "done": t.done}
        for t in tasks
    ]


@app.put("/tasks/{task_id}")
def update_task(task_id: int, data: TaskReq, user=Depends(get_current_user)):
    """Change the title of an existing task."""
    # Two conditions: the right task, and it belongs to the caller.
    task = session.query(Task).filter(
        Task.id == task_id,
        Task.user_id == user.id,
    ).first()

    # 404 rather than 403: telling the caller the task exists but is
    # someone else's would leak information.
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # SQLAlchemy tracks the change, so no session.add() is needed
    task.title = data.title
    session.commit()

    return {"message": "Task updated", "new_title": task.title}


@app.patch("/tasks/{task_id}/done")
def mark_done(task_id: int, user=Depends(get_current_user)):
    """Toggle a task between done and not done."""
    task = session.query(Task).filter(
        Task.id == task_id,
        Task.user_id == user.id,
    ).first()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Flip the current value: True -> False, False -> True
    task.done = not task.done
    session.commit()

    if task.done:
        return {"message": f"Task '{task.title}' is done"}
    return {"message": f"Task '{task.title}' is not done yet"}


@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, user=Depends(get_current_user)):
    """Remove a task permanently."""
    task = session.query(Task).filter(
        Task.id == task_id,
        Task.user_id == user.id,
    ).first()

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # delete() expects the object itself, not the id
    session.delete(task)
    session.commit()

    return {"message": f"Task '{task.title}' removed"}