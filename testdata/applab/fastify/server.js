// A small Fastify API with Fastify's own logger ({ logger: true }), as most Fastify apps do. Fastify writes
// each request as two pino lines, "incoming request" and "request completed", joined by reqId.
const fastify = require("fastify")({ logger: true });
fastify.post("/auth/login", async (req, reply) => {
  const { username, password } = req.body || {};
  if (username === "alice" && password === "Summer2026!") return { token: "t" };
  req.log.warn(`Failed login for ${username} from ${req.ip}`);
  return reply.code(401).send({ error: "invalid credentials" });
});
fastify.get("/api/items", async (req, reply) => {
  if (String(req.query.id).includes("'")) {
    req.log.error(`QueryFailedError: syntax error at or near "${req.query.id}"`);
    return reply.code(500).send({ error: "server error" });
  }
  return [];
});
fastify.listen({ port: 8080, host: "0.0.0.0" });
