import { createHmac, timingSafeEqual } from "node:crypto";

const AZURE_BASE = (tenantId: string) =>
  `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0`;

export function getAuthUrl(): string {
  const params = new URLSearchParams({
    client_id: process.env.AZURE_CLIENT_ID!,
    response_type: "code",
    redirect_uri: process.env.REDIRECT_URI!,
    scope: "openid profile email",
    response_mode: "query",
  });

  return `${AZURE_BASE(process.env.AZURE_TENANT_ID!)}/authorize?${params}`;
}

export function getLogoutUrl(): string {
  const params = new URLSearchParams({
    post_logout_redirect_uri: process.env.REDIRECT_URI!.replace(
      "/auth/callback",
      "/"
    ),
  });

  return `${AZURE_BASE(process.env.AZURE_TENANT_ID!)}/logout?${params}`;
}

interface TokenPayload {
  name: string;
  email: string;
  exp: number;
}

export async function exchangeCodeForToken(
  code: string
): Promise<TokenPayload> {
  const body = new URLSearchParams({
    client_id: process.env.AZURE_CLIENT_ID!,
    client_secret: process.env.AZURE_CLIENT_SECRET!,
    code,
    redirect_uri: process.env.REDIRECT_URI!,
    grant_type: "authorization_code",
    scope: "openid profile email",
  });

  const res = await fetch(
    `${AZURE_BASE(process.env.AZURE_TENANT_ID!)}/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed: ${res.status} ${text}`);
  }

  const { id_token } = (await res.json()) as { id_token: string };
  const payload = JSON.parse(
    Buffer.from(id_token.split(".")[1], "base64url").toString()
  ) as Record<string, unknown>;

  return {
    name: (payload.name as string) ?? "",
    email:
      (payload.preferred_username as string) ??
      (payload.email as string) ??
      "",
    exp: payload.exp as number,
  };
}

export function signCookie(payload: TokenPayload): string {
  const data = JSON.stringify(payload);
  const encoded = Buffer.from(data).toString("base64url");
  const sig = createHmac("sha256", process.env.COOKIE_SECRET!)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${sig}`;
}

export function verifyCookie(value: string): TokenPayload | null {
  const dot = value.lastIndexOf(".");
  if (dot === -1) return null;

  const encoded = value.slice(0, dot);
  const sig = value.slice(dot + 1);

  const expected = createHmac("sha256", process.env.COOKIE_SECRET!)
    .update(encoded)
    .digest("base64url");

  if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;

  const payload = JSON.parse(
    Buffer.from(encoded, "base64url").toString()
  ) as TokenPayload;

  if (payload.exp * 1000 < Date.now()) return null;

  return payload;
}
