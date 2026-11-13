// A small Express API, logging with morgan "combined" as most Express apps do.
const express = require("express");
const morgan = require("morgan");
const app = express();
app.set("trust proxy", false);
app.use(morgan("combined"));
app.use(express.json());
app.post("/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === "alice" && password === "Summer2026!") return res.json({ token: "t" });
  console.warn(`Failed login for ${username} from ${req.ip}`);
  res.status(401).json({ error: "invalid credentials" });
});
app.get("/api/items", (req, res) => {
  if (String(req.query.id).includes("'")) {
    console.error(`QueryFailedError: syntax error at or near "${req.query.id}"`);
    return res.status(500).json({ error: "server error" });
  }
  res.json([]);
});
app.listen(8080, () => console.log("listening on 8080"));
