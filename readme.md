# Fund Fraud Detection API

Real-time transaction fraud detection using FastAPI, XGBoost, and PostgreSQL.
Full auth lifecycle + idempotent predictions.

---

## Tech Stack

- FastAPI
- XGBoost
- PostgreSQL
- SQLAlchemy
- OAuth2 + JWT
- bcrypt
- Pydantic v2

---

## Overview

Takes 28 anonymised PCA features + transaction amount and returns:
- Fraud probability
- Fraud / Legit classification

Average latency: ~55ms per request

---

## System Design Highlights

### Model Selection
- Chose XGBoost over Random Forest for faster inference on tabular data
- Fraud threshold tuned to 0.23 (precision-recall tradeoff)
- Reduces false negatives on imbalanced classes

---

### Idempotent Predictions
- Each request hashed as SHA-256(user_id + sorted feature values)
- Hash stored with UNIQUE constraint in PostgreSQL
- Duplicate submissions return stored result — no re-inference
- Race condition handled at DB level: concurrent duplicates get unique violation, not double-insert

---

### Auth Lifecycle
- Email verification token on signup
- JWT access tokens (15 min) + refresh tokens (7 days)
- bcrypt password hashing
- Account lockout after 5 consecutive failures
- Auto-releases after 15 min via DB timestamp — no background job needed

---

### Error Handling
- 4 error categories: auth, validation, model, DB
- Consistent response schema: `{code, message, detail}`
- No stack traces exposed to clients

---

### Model Loading
- Loaded once at startup — eliminates per-request disk I/O
- Avg latency: ~55ms (Postman, 30 requests, local)

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/register | Register + trigger email verification |
| POST | /auth/login | Get JWT access + refresh tokens |
| POST | /auth/refresh | Refresh access token |
| POST | /predict | Submit transaction, get fraud classification |

---

## Local Setup
```bash
git clone https://github.com/SVChaithanya/Fund-Fraud-Detection-API
cd Fund-Fraud-Detection-API
pip install -r requirements.txt
uvicorn main:app --reload
```

Swagger UI: http://localhost:8000/docs

---

## Known Limitations

- Tested with 30 requests locally — not a distributed load test
- Model trained on Kaggle credit card fraud dataset — real-world performance may vary
- Email verification currently logs the token (no actual email service integrated)
