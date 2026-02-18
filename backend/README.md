PurpleTeam Dashboard Backend

FastAPI backend providing JWT authentication and API endpoints for PurpleTeam Dashboard.

## Installation

```bash
pip install -r requirements.txt
```

## Running

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Access interactive API docs at http://localhost:8000/docs

## Features

- JWT token-based authentication
- User endpoint example
- Extendable for agent data ingest and alert APIs
