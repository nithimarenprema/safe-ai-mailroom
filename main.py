from fastapi import FastAPI

app = FastAPI(title="Safe AI Mailroom")

@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "Safe AI Mailroom"
    }
