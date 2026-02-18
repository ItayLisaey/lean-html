import "dotenv/config";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { setCookie, deleteCookie } from "hono/cookie";
import {
  exchangeCodeForToken,
  getLogoutUrl,
  signCookie,
} from "./auth.ts";
import { authMiddleware, AUTH_COOKIE } from "./auth-middleware.ts";

const app = new Hono();

// --- Unprotected routes ---

app.get("/auth/callback", async (c) => {
  const code = c.req.query("code");
  if (!code) return c.text("Missing code parameter", 400);

  const payload = await exchangeCodeForToken(code);

  setCookie(c, AUTH_COOKIE, signCookie(payload), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
    path: "/",
    maxAge: payload.exp - Math.floor(Date.now() / 1000),
  });

  return c.redirect("/");
});

app.get("/logout", (c) => {
  deleteCookie(c, AUTH_COOKIE, { path: "/" });
  return c.redirect(getLogoutUrl());
});

// --- Protected routes ---

app.use("/*", authMiddleware);
app.use("/*", serveStatic({ root: "./public" }));

// --- Start ---

const port = Number(process.env.PORT) || 3000;

serve({ fetch: app.fetch, port }, () => {
  console.log(`Listening on http://localhost:${port}`);
});
