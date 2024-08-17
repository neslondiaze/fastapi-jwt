from typing import Annotated
from datetime import datetime, timedelta
from wsgiref import headers

from fastapi import FastAPI, Request, Form, HTTPException, Cookie
from fastapi.templating  import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import jwt, JWTError


SECRETE_KEY = "4469fc8151bad144147edfc4c88c7f16a3d01b4848597316d0626ef6e8e33ab4"
TOKEN_SCONDS_EXP = 60

db_users ={
    "nelson":{
        "id": 0,
        "username": "nelson",
        "password": "cielo0#hash"
    },
    "noris":{
        "id": 1,
        "username": "noris",
        "password": "jehoba#hash"
    },
    "nedp":{
        "id":2,
        "username": "nedp",
        "password": "cielo0"
    }
}

app = FastAPI()

Jinja2_template = Jinja2Templates(directory="templates")

def get_user(username: str, db: list):
   if username in db:
      return db[username]


def authenticate_user(password: str, password_plane: str):
    password_clean = password.split("#")[0]
    if password_plane == password_clean:
        return True
    return False


def create_token(data: list):
     data_token = data.copy()
     data_token["exp"] = datetime.utcnow() + timedelta(seconds=TOKEN_SCONDS_EXP)
     token_jwt = jwt.encode(data_token, key=SECRETE_KEY, algorithm="HS256")
     return token_jwt

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    return Jinja2_template.TemplateResponse("index.html", {"request": request})

@app.get("/users/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, access_token: Annotated[str | None, Cookie()] = None):
    if access_token is None:
        return RedirectResponse("/", status_code=302)
    try:
        data_user = jwt.decode(access_token, key=SECRETE_KEY, algorithms=["HS256"])
        if get_user(data_user["username"], db_users) is None:
            return RedirectResponse("/", status_code=302)
    except JWTError:
        return RedirectResponse("/", status_code=302)

    return Jinja2_template.TemplateResponse("dashboard.html", {"request": request})

@app.post("/users/login")
def login(username: Annotated[str, Form()], password: Annotated[str, Form()]):
    user_data = get_user(username, db_users)

    if user_data is None:
        raise HTTPException(
            status_code=401,
            detail="Username or password not Authorization"
        )
    if not authenticate_user(user_data["password"], password):
        raise HTTPException(
            status_code=401,
            detail="Username or password not Authorization"
        )  
    token = create_token({"username": user_data["username"]})
    
    return RedirectResponse(
        "/users/dashboard",
        status_code=302,
        headers={"set-cookie": f"access_token={token}; Max-Agen={TOKEN_SCONDS_EXP}"}
    )

@app.post("/users/logout")
def logout():
    return RedirectResponse("/", status_code=302, headers={
        "set-cookie": "access_token=; Max-Age=0"
    })