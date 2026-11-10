from flask import Flask

app = Flask(__name__)


@app.get("/")
def hello() -> str:
    return "hello"
