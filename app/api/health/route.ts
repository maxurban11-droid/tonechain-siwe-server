// app/api/health/route.ts
import { NextResponse } from "next/server"
import { withCORS } from "@/helpers/cors"

export function OPTIONS(req: Request) {
  return withCORS(req, new NextResponse(null, { status: 204 }))
}

export async function GET(req: Request) {
  return withCORS(req, NextResponse.json({ status: "ok" }))
}
