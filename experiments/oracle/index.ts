import { serve } from "bun";
import { Hono } from "hono";
import { logger } from "hono/logger";

import { customDecode64, decryptRsa } from "./secure/crypto";
import { parseLooseQuery, parsePclogParams } from "./secure/params";
import { type HelloResponse, type PclogResponse } from "./shared/types";
import home from "./browser/index.html";

const SALT = 8 as const;

const api = new Hono().basePath("/op");
api.use("*", logger());

api.onError((err, c) => {
  console.error(`[ERROR] ${c.req.path}`);
  console.error(`Message: ${err.message}`);
  if (err.stack) {
    console.error(`Stack trace:\n${err.stack}`);
  }
  return c.json({ error: "Internal server error" }, 500);
});

// Op endpoints
api.post("/47a3", async (c) => {
  const { data } = await c.req.json<{ data: HelloResponse }>();
  if (!data) {
    return c.json({ error: "Missing data" }, 400);
  }
  return c.json({
    pem: customDecode64(data.client_public_key, SALT).toString("utf-8"),
  });
});

api.post("/9f21", async (c) => {
  const { data } = await c.req.json<{ data: PclogResponse }>();
  if (!data) {
    return c.json({ error: "Missing data" }, 400);
  }
  const outer = customDecode64(data.pclog_data, SALT).toString("utf-8");
  const params = parsePclogParams(outer);

  const key = params.key;
  const innerData = params.data;
  const innerSalt = params.salt;

  // No encryption
  if (params.alg === 0) {
    return c.json({
      profile: parseLooseQuery(atob(params.data)),
    });
  }

  console.log(params);

  return c.json({
    success: true,
    key,
    innerData,
    innerSalt,
  });
});

// Main Bun server
const server = serve({
  routes: {
    "/": home,
    "/op/*": api.fetch,
  },
  development: Bun.env.NODE_ENV !== "production" && {
    hmr: true,
    console: true,
  },
});

console.log(`[*] Server running at ${server.url}`);
