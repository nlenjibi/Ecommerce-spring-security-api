import { cookies } from "next/headers";
import { redirect } from "next/navigation";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:9190/api";

export async function getAccessToken(): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get("access_token")?.value ?? null;
}

export async function getRefreshToken(): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get("refresh_token")?.value ?? null;
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const accessToken = await getAccessToken();

  if (!accessToken) {
    redirect("/auth/login");
  }

  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
      ...options.headers,
    },
    cache: "no-store",
  });

  if (res.status === 401) {
    const refreshed = await tryRefreshToken();
    if (!refreshed) {
      redirect("/auth/login");
    }
    const newToken = await getAccessToken();
    return fetch(`${API_URL}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${newToken}`,
        ...options.headers,
      },
      cache: "no-store",
    });
  }

  return res;
}

async function tryRefreshToken(): Promise<boolean> {
  const refreshToken = await getRefreshToken();
  if (!refreshToken) return false;

  const res = await fetch(`${API_URL}/v1/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken }),
    cache: "no-store",
  });

  if (!res.ok) return false;

  const json = await res.json();
  const cookieStore = await cookies();
  const isProduction = process.env.NODE_ENV === "production";

  cookieStore.set("access_token", json.data.accessToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: json.data.expiresIn,
    path: "/",
  });

  return true;
}

export async function isAuthenticated(): Promise<boolean> {
  const token = await getAccessToken();
  return !!token;
}
