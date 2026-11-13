# A small Flask API on its built-in server, as many small apps run it in a container.
import logging

from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)


@app.post("/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    if body.get("username") == "alice" and body.get("password") == "Summer2026!":
        return jsonify(token="t")
    app.logger.warning("Failed login for %s from %s", body.get("username"), request.remote_addr)
    return jsonify(error="invalid credentials"), 401


@app.get("/api/items")
def items():
    item = request.args.get("id", "")
    if "'" in item:
        app.logger.error('sqlite3.OperationalError: SQLITE_ERROR near "%s": syntax error', item)
        return jsonify(error="server error"), 500
    return jsonify([])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
