# Task Manager API

A REST API for managing personal tasks, built with FastAPI and SQLAlchemy.

## Features

- User registration with bcrypt password hashing
- Login with credential verification
- Create, read, update, and delete tasks
- Mark tasks as done or not done
- Filter tasks by completion status

## Tech Stack

- Python
- FastAPI
- SQLAlchemy (SQLite)
- bcrypt

## Setup

```bash
pip install fastapi uvicorn sqlalchemy bcrypt
uvicorn main:app --reload
```

Then open http://127.0.0.1:8000/docs

## Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | /register | Create a new account |
| POST | /login | Log in and get user id |
| POST | /tasks/{user_id} | Add a task |
| GET | /tasks/{user_id} | List all tasks |
| GET | /tasks/{user_id}/filter?done=true | Filter tasks |
| PUT | /tasks/{task_id} | Update task title |
| PATCH | /tasks/{task_id}/done | Toggle done status |
| DELETE | /tasks/{task_id} | Delete a task |
