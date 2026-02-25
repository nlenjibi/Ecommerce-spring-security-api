import { NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:9190/api";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const error = searchParams.get("error");

  if (error || !code) {
    return NextResponse.redirect(new URL("/auth/login?error=oauth2_failed", req.url));
  }

  let authData: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
    user: {
      id: number;
      email: string;
      firstName: string;
      lastName: string;
      username: string;
      role: string;
    };
    provider: string;
  };

  try {
    const res = await fetch(`${API_URL}/v1/auth/oauth2/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
      cache: "no-store",
    });

    if (!res.ok) {
      console.error("OAuth2 exchange failed:", res.status, await res.text());
      return NextResponse.redirect(new URL("/auth/login?error=exchange_failed", req.url));
    }

    const json = await res.json();
    authData = json.data;
  } catch (err) {
    console.error("OAuth2 exchange error:", err);
    return NextResponse.redirect(new URL("/auth/login?error=server_error", req.url));
  }

  const cookieStore = await cookies();
  const isProduction = process.env.NODE_ENV === "production";

  cookieStore.set("access_token", authData.accessToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: authData.expiresIn,
    path: "/",
  });

  // Also set auth-token cookie for AuthContext compatibility
  cookieStore.set("auth-token", authData.accessToken, {
    httpOnly: false,
    secure: isProduction,
    sameSite: "lax",
    maxAge: authData.expiresIn,
    path: "/",
  });

  cookieStore.set("refresh_token", authData.refreshToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 60 * 60 * 24 * 7,
    path: "/",
  });

  // Set user data in a cookie that the client can read
  // The AuthContext will look for this and set it in localStorage
  const userData = JSON.stringify({
    id: authData.user?.id,
    email: authData.user?.email,
    firstName: authData.user?.firstName,
    lastName: authData.user?.lastName,
    username: authData.user?.username,
    role: authData.user?.role,
  });
  
  cookieStore.set("oauth2_user", userData, {
    httpOnly: false, // Client needs to read this
    secure: isProduction,
    sameSite: "lax",
    maxAge: authData.expiresIn,
    path: "/",
  });

  const destination = authData.user?.role === "ADMIN" 
    ? "/dashboard/admin" 
    : authData.user?.role === "STAFF" 
      ? "/dashboard/staff" 
      : "/";
  
  return NextResponse.redirect(new URL(destination, req.url));
}
