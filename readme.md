# Fund Fraud Detection API

A backend API for detecting fraudulent transactions using **Machine Learning (XGBoost)**, secured with **email/password authentication**, built with **FastAPI**.

Users can register, verify their email, login, refresh tokens, and predict if a transaction is fraudulent based on transaction features.

---

## 🚀 Features

### Fraud ML
- Uses **XGBoost Classifier** to detect fraudulent transactions.
- Predicts `Class` of a transaction (Fraud vs Legit) using 28 anonymized features (`V1–V28`) and `Amount`.
- Includes custom threshold (`FRAUD_THRESHOLD`) for labeling fraud.
- Preprocessing with **median imputation** for numeric features.
- Model saved as `model.pkl` and loaded for API predictions.

### Auth & Security
- User registration with email/password.
- Email verification via token.
- Login with access & refresh JWT tokens.
- Password reset/change support.
- Account lockout after multiple failed login attempts.
- Logging of predictions and errors.

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/registre` | POST | Register new user |
| `/auth/verification` | POST | Verify email with token |
| `/auth/login` | POST | Login and get access & refresh tokens |
| `/auth/refresh` | POST | Refresh tokens |
| `/auth/predict` | POST | Predict if transaction is Fraud or Legit (requires auth) |
| `/auth/forgot/passkey` | POST | Request password reset token |
| `/auth/change/passkey` | POST | Change password with reset token |
| `/auth/me` | GET | Get current user info |

---

## ⚙️ Requirements

- Python 3.9+
- FastAPI
- Uvicorn
- XGBoost
- scikit-learn
- pandas
- pydantic
- passlib
- python-jose
- joblib

Install dependencies:

pip install -r requirements.txt


###🏃 How to Run

1.Clone the repo:
     git clone https://github.com/SVChaithanya/Fund-Fraud-Detection-API.git
      cd Fund-Fraud-Detection-API
2.Install dependencies:
     pip install -r requirements.txt
3.Run the API locally:
     uvicorn main:app --reload
4.Access the API:
     http://127.0.0.1:8000
5.Test endpoints using Postman or any HTTP client.

###📦 ML Model

-Trained on credit card/fund transaction dataset.
-FRAUD_THRESHOLD = 0.23 for classifying a transaction as Fraud.
-Returns:
    -predict_class → 0 (Legit) / 1 (Fraud)
    -probability → confidence score
    -status → Fraud / Legit

###📝 Logging

-Predictions logged to logs/predictions.log.
-Logs include input, prediction, probability, status, and requesting user.

###🔒 Security

-Passwords hashed using bcrypt.
-JWT tokens used for authentication.
-Refresh tokens stored securely.
-User accounts lock after repeated failed login attempts.

###🔗 Future Work

-Add PostgreSQL database with SQLAlchemy.
-Deploy API to Render / AWS for public access.
-Add Docker deployment.
-Implement threshold tuning and imbalanced class handling.
-Add analytics for fraud patterns.

##📂Project Structure

├── main.py              # FastAPI + endpoints + auth + ML integration
├── model.pkl            # Trained ML model
├── requirements.txt     # Dependencies
├── logs/                # Prediction logs
└── README.md
