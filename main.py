"""
Task Manager API — built with FastAPI and SQLAlchemy.

Features:
    - User registration with bcrypt password hashing
    - Login with credential verification
    - Full CRUD for tasks (create, read, update, delete)
    - Marking tasks as done / not done
    - Filtering tasks by completion status

Run with:
    uvicorn main:app --reload

Interactive docs:
    http://127.0.0.1:8000/docs
"""

import bcrypt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from database import Session, User, Task

app = FastAPI(title="Task Manager API")
session = Session()


# ─────────────────────────────────────────────
#  Request models
#  These define the shape of the JSON the client sends
# ─────────────────────────────────────────────

class UserReq(BaseModel):
    """Body for register and login requests."""
    username: str
    password: str


class TaskReq(BaseModel):
    """Body for creating or updating a task."""
    title: str


# ─────────────────────────────────────────────
#  Authentication
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

    # Hash the password before storing it.
    # gensalt() adds random data, so identical passwords
    # produce different hashes.
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
def login(data: UserReq):
    """Verify credentials and return the user id."""
    user = session.query(User).filter(
        User.username == data.username
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # checkpw compares the plain password against the stored hash
    is_correct = bcrypt.checkpw(
        data.password.encode(),
        user.password.encode(),
    )

    if not is_correct:
        raise HTTPException(status_code=401, detail="Wrong password")

    return {"message": "Welcome", "user_id": user.id}


# ─────────────────────────────────────────────
#  Tasks
# ─────────────────────────────────────────────

@app.post("/tasks/{user_id}")
def add_task(user_id: int, data: TaskReq):
    """Create a task owned by the given user."""
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # done defaults to False, so it is not set here
    new_task = Task(title=data.title, user_id=user_id)
    session.add(new_task)
    session.commit()

    return {
        "message": f"Task '{data.title}' added successfully",
        "task_id": new_task.id,
    }


@app.get("/tasks/{user_id}")
def get_tasks(user_id: int):
    """List every task belonging to the given user."""
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Only return tasks owned by this user
    tasks = session.query(Task).filter(Task.user_id == user_id).all()

    return [
        {"id": t.id, "title": t.title, "done": t.done}
        for t in tasks
    ]


@app.get("/tasks/{user_id}/filter")
def filter_tasks(user_id: int, done: bool = None):
    """
    List tasks filtered by completion status.

    Example:
        /tasks/1/filter?done=true   -> only completed tasks
        /tasks/1/filter?done=false  -> only pending tasks
        /tasks/1/filter             -> all tasks
    """
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    query = session.query(Task).filter(Task.user_id == user_id)

    # Only narrow the query if the client asked for a status
    if done is not None:
        query = query.filter(Task.done == done)

    tasks = query.all()

    return [
        {"id": t.id, "title": t.title, "done": t.done}
        for t in tasks
    ]


@app.put("/tasks/{task_id}")
def update_task(task_id: int, data: TaskReq):
    """Change the title of an existing task."""
    task = session.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # SQLAlchemy tracks the change, so no session.add() is needed
    task.title = data.title
    session.commit()

    return {"message": "Task updated", "new_title": task.title}


@app.patch("/tasks/{task_id}/done")
def mark_done(task_id: int):
    """Toggle a task between done and not done."""
    task = session.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Flip the current value: True -> False, False -> True
    task.done = not task.done
    session.commit()

    if task.done:
        return {"message": f"Task '{task.title}' is done"}
    return {"message": f"Task '{task.title}' is not done yet"}


@app.delete("/tasks/{task_id}")
def delete_task(task_id: int):
    """Remove a task permanently."""
    task = session.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # delete() expects the object itself, not the id
    session.delete(task)
    session.commit()

    return {"message": f"Task '{task.title}' removed"}