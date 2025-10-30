import { NextResponse } from "next/server"
import { cors, preflight } from "@/helpers/cors"

export const dynamic = "force-dynamic"

export function OPTIONS(req: Request) {
  return preflight(req)
}

export function GET(req: Request) {
  return cors(req, NextResponse.json({ status: "ok" }))
}
