import uvicorn
from fastapi import FastAPI
from models.burp import BurpContent

app = FastAPI()


@app.get("/")
async def test():
    return {"message": "Hello World"}


@app.post("/analyze")
async def analyze_burp(burp_content: BurpContent):
    return {"message": "Hello World"}


if __name__ == "__main__":
    uvicorn.run("main:app", host='0.0.0.0', port=8080, reload=True)
