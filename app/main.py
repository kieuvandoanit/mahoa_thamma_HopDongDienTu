from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.routes import contracts

app = FastAPI(title="E-Contract Demo")
app.include_router(contracts.router)
app.mount("/storage", StaticFiles(directory="storage"), name="storage")

templates = Jinja2Templates(directory="app/templates")

@app.get("/")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
