# FastAPI Google OAuth & User Registration

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Set up your `.env` file with your PostgreSQL and Google OAuth credentials.
3. Run database migrations to create tables.
4. Start the server:
   ```bash
   uvicorn main:app --reload
   ```

## Endpoints

- `POST /auth/register` — Register with email/password
- `POST /auth/login` — Login with email/password
- `GET /auth/google/login` — Start Google OAuth
- `GET /auth/google/callback` — Google OAuth callback
