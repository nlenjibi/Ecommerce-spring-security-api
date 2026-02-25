"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:9190/api";

export async function loginAction(formData: FormData) {
  const email = formData.get("email") as string;
  const password = formData.get("password") as string;

  const res = await fetch(`${API_URL}/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
    cache: "no-store",
  });

  if (!res.ok) {
    const err = await res.json();
    return { error: err.message ?? "Login failed" };
  }

  const json = await res.json();
  const data = json.data;
  const cookieStore = await cookies();
  const isProduction = process.env.NODE_ENV === "production";

  cookieStore.set("access_token", data.accessToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: data.expiresIn,
    path: "/",
  });

  cookieStore.set("refresh_token", data.refreshToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 60 * 60 * 24 * 7,
    path: "/",
  });

  const role = data.user?.role ?? data.role;
  const destination = role === "ADMIN" 
    ? "/dashboard/admin" 
    : role === "STAFF" 
      ? "/dashboard/staff" 
      : "/";
  
  redirect(destination);
}
