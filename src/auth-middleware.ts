import { createMiddleware } from "hono/factory";
import { getCookie } from "hono/cookie";
import { getAuthUrl, verifyCookie } from "./auth.ts";

export const AUTH_COOKIE = "lean_auth";

export type AuthUser = { name: string; email: string };

export const authMiddleware = createMiddleware<{
  Variables: { user: AuthUser };
}>(async (c, next) => {
  const cookie = getCookie(c, AUTH_COOKIE);

  if (cookie) {
    const payload = verifyCookie(cookie);
    if (payload) {
      c.set("user", { name: payload.name, email: payload.email });
      return next();
    }
  }

  return c.redirect(getAuthUrl());
});
