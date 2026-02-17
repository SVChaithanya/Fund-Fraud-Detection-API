import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split,RandomizedSearchCV

from xgboost import XGBClassifier

from sklearn.metrics import f1_score,accuracy_score,roc_auc_score,recall_score



df = pd.read_csv(r"creditcard.csv")
df.drop(columns="Time",inplace=True)



X = df.drop(columns='Class')
y=df['Class']

X_train,X_test,y_train,y_test = train_test_split(X,y,test_size=0.2,stratify=y,random_state=42)

num = X.select_dtypes(include='number').columns.tolist()

num_line = Pipeline(steps=[(
    "simple",SimpleImputer(strategy="median")
)])

process = ColumnTransformer(transformers=[(
    'num',num_line,num
)])



pipe = Pipeline(steps=[
    ("process",process),
    ("xgbm",XGBClassifier(random_state=42))
])

pipe_param = {
    "xgbm__n_estimators":[300,500,700],
    "xgbm__learning_rate":[0.01,0.05,0.2],
    "xgbm__max_depth":[5,7,9],
    "xgbm__gamma":[2,5],
    "xgbm__subsample":[0.6,0.8,1.0],
    "xgbm__colsample_bytree":[0.5,0.7,1.0]
}

XCV = RandomizedSearchCV(
    pipe,pipe_param,n_iter=100,n_jobs=1,cv=5,verbose=2,
    scoring="roc_auc",random_state=42
    )
XCV.fit(X_train,y_train)
param = XCV.best_estimator_
print(param)

import joblib

joblib.dump(param,"model.pkl")

