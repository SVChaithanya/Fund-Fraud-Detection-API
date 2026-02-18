
from fastapi import FastAPI,HTTPException,Depends
from pydantic import BaseModel,EmailStr,Field
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from passlib.context import CryptContext
from datetime import datetime,timedelta
import joblib , pandas as pd,hashlib,uuid
from jose import jwt,JWTError
import logging,os

model = joblib.load("model.pkl")

app = FastAPI()

FRAUD_THRESHOLD = 0.23


users ={}
refresh_stored_token = {}
blacklist_gti ={}

os.makedirs("logs",exist_ok=True)
logging.basicConfig(
    filename="logs/predictions.log",
    level=logging.DEBUG,
    format="%(asctime)s -%(levelname)s -%(message)s"
    )

class fundsimput(BaseModel):
    V1:float
    V2:float
    V3:float
    V4:float
    V5:float
    V6:float
    V7:float
    V8:float
    V9:float
    V10:float
    V11:float
    V12:float
    V13:float
    V14:float
    V15:float
    V16:float
    V17:float
    V18:float
    V19:float
    V20:float
    V21:float
    V22:float
    V23:float
    V24:float
    V25:float
    V26:float
    V27:float
    V28:float
    Amount:float

class registration(BaseModel):
    email:EmailStr
    password:str=Field(min_length=6)

class refreshrequest(BaseModel):
    refresh:str

class forgotpasskey(BaseModel):
    token : str
    new_password : str=Field(min_length=6)


SECURITY = "SECURITY_KEY"
ALGORITHM = "HS256"

ACCESS_TOKEN_EXP_MIN = 15
REFRESH_TOKEN_EXP_DAY =7
MAX_FAILED_ATTENDS = 5
LOCK_EXP_MIN =15
RESET_TOKEN_EXP_MIN = 15

pwd = CryptContext(schemes=["bcrypt"])

def hashed(password:str):
    return pwd.hash(password)
def verify(plan,hash):
    return pwd.verify(plan,hash)

@app.post("/auth/registre")
def registre(user:registration):
    if user.email in users:
        raise HTTPException(status_code=400,detail="the email is registrated change the email address...")
    verified_token = str(uuid.uuid4())
    users[user.email]={
        "email":user.email,
        "password":hashed(user.password),
        "role":"admin",
        "is_verified":False,
        "verification_token":verified_token,
        "token_version":0,
        "failed_attempts":0,
        "lock_unilt":None,
        "reset_token":None,
        "reset_exp_min":None
    }
    return{
        "verification_token":verified_token,
        "status":"the email is registred successfully..."
    }

@app.post("/auth/verification")
def verification(token:str):
    for user in users.values():
        if user["verification_token"] == token:
            user["is_verified"]=True
            user["verification_token"]=None
            return{
                "message":"this email of the token is verified"
            }



def CREATE_ACCESS_TOKEN(user:dict):
    jti=str(uuid.uuid4())
    payload = {
        "sub":user['email'],
        "role":user["role"],
        'token_version':user["token_version"],
        "jti":jti,
        "iat":datetime.utcnow(),
        "exp":datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXP_MIN)
    }
    return jwt.encode(payload,SECURITY,algorithm=ALGORITHM)
    
def hashed_token_refresh(token:str):
    return hashlib.sha256(token.encode()).hexdigest()

def CREATE_REFRESH_TOKEN(user:dict):
    row_token = str(uuid.uuid4())
    hashs = hashed_token_refresh(row_token)  
    refresh_stored_token[hashs] = {
        "email":user["email"],
        "token_version":user["token_version"],
        "exp":datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXP_DAY)
    }
    return row_token

@app.post("/auth/login")
def login(from_data:OAuth2PasswordRequestForm=Depends()):
    user = users.get(from_data.username)
    if not user:
        raise HTTPException(status_code=401,detail="the email is not registrated...")
    if not user["is_verified"]:
        raise HTTPException(status_code=401,detail="the email is registrated but not verified ...")
    if user["lock_unilt"] and datetime.utcnow() > user["lock_unilt"]:
        raise HTTPException(status_code=401,detail="the lock unilt time up...")
    if not verify(from_data.password,user['password']):
        user['failed_attempts'] +=1
        if user['failed_attempts'] >= MAX_FAILED_ATTENDS:
            user["lock_unilt"] = datetime.utcnow() + timedelta(minutes=LOCK_EXP_MIN)
        raise HTTPException(status_code=401,detail="the password is not matched...")
    user["failed_attempts"] =0
    access_token = CREATE_ACCESS_TOKEN(user)
    refresh_token = CREATE_REFRESH_TOKEN(user)
    return{
        "access_token":access_token,
        "refresh_token":refresh_token
    }

@app.post("/auth/refresh")
def refresh(data:refreshrequest):
    hashs = hashed_token_refresh(data.refresh)
    stored = refresh_stored_token.get(hashs)

    if not stored:
        raise HTTPException(status_code=401,detail="the token is not found")
    user = users.get(stored["email"])
    if not user:
        raise HTTPException(status_code=401,detail="the email is not found")
    if user["token_version"] != stored['token_version']:
        raise HTTPException(status_code=403,detail="the token version not matched")
    del refresh_stored_token[hashs] 
    new_access_token = CREATE_ACCESS_TOKEN(user)
    new_refresh_token = CREATE_REFRESH_TOKEN(user) 

    return{
        "new_access_token":new_access_token,
        "new_refresh_token":new_refresh_token
    }   

OAuth2_schema = OAuth2PasswordBearer(tokenUrl="/auth/login")
def GET_CURRENT_TOKEN(token:str=Depends(OAuth2_schema)):
    try:
        payload=jwt.decode(token,SECURITY,algorithms=[ALGORITHM])
        if payload["jti"] in blacklist_gti:
            raise HTTPException(status_code=401,detail="token revoked")
        user = users.get(payload["sub"])
        if not user:
            raise HTTPException(status_code=401,detail="user is not found")
        if payload["token_version"] != user["token_version"]:
            raise HTTPException(status_code=401,detail="token invalidated")
        return user
    except JWTError:
        raise HTTPException(status_code=401,detail="invalid or expired")
    


@app.post("/auth/predict")
def predicted(data:fundsimput,user=Depends(GET_CURRENT_TOKEN)):
    df = pd.DataFrame([data.dict()])


    try:
        prediction = model.predict(df)[0]
        pred_prob = model.predict_proba(df)[0][1]
        if pred_prob >= FRAUD_THRESHOLD:
            status = "Fraud"
        else:
            status= "Legit"
        logging.info({
            "input":data.dict(),
            "predict_class":int(prediction),
            "probability":float(pred_prob),
            "status":status,
            "request_by":user["email"]
        })    
        return{
            "predict_class":int(prediction),
            "probability":float(pred_prob),
            "requested_by":user["email"],
            "status":status
        }
    except Exception as e:
        logging.error({
            "input":data.dict(),
            "error":e
        })
        raise e


@app.post("/auth/forgot/passkey")
def forgot_passkey(email:str):
    user = users.get(email)
    if not user:
        raise HTTPException(status_code=401,detail="user not found")
    reset_token = str(uuid.uuid4())
    user["reset_token"] = reset_token
    user["reset_exp_min"] = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXP_MIN)
    return{
        "reset_token":reset_token
    }   
 

@app.post("/auth/change/passkey")
def change_passkey(data:forgotpasskey):
    for user in users.values():
        if user["reset_token"] == data.token:
            if user["reset_exp_min"] < datetime.utcnow():
                raise HTTPException(status_code=400,detail="reset token expired")
            user["password"] = hashed(data.new_password)
            user["reset_token"] = None
            user["reset_exp_min"] = None
            user["token_version"] +=1
            return { "message":"passkey is updated done" }
        
    raise HTTPException(status_code=400,detail="invalid reset token")
@app.get("/auth/me")
def me(user=Depends(GET_CURRENT_TOKEN)):
    return{
        "email":user["email"],
        "role":user["role"]
    }
