import { NextResponse, type NextRequest } from "next/server";
import { withCors, handleOptions } from "@/utils/cors";
import { keccak256 } from "viem";           // falls schon vorhanden
import { recoverAddress, hashMessage } from "viem"; // oder ethers v5: utils.hashMessage / recoverAddress

export async function OPTIONS(req: NextRequest) {
  return handleOptions(req);
}

export async function POST(req: NextRequest) {
  try {
    const { message, signature } = await req.json().catch(() => ({}));
    if (!message || !signature) {
      return withCors(req, NextResponse.json({ ok:false, error:"Invalid payload" }, { status:400 }));
    }

    const nonce = req.cookies.get("tc_nonce")?.value;
    if (!nonce) {
      return withCors(req, NextResponse.json({ ok:false, error:"Nonce cookie missing or expired" }, { status:400 }));
    }

    // 1) Signatur verifizieren (Adresse aus Signatur rekonstruieren)
    let recovered: `0x${string}`;
    try {
      const digest = hashMessage(message); // viem
      recovered = await recoverAddress({ hash: digest, signature });
    } catch {
      return withCors(req, NextResponse.json({ ok:false, error:"Invalid signature" }, { status:400 }));
    }

    // 2) Optionale Domain-/Nonce-Prüfung aus der Message (tolerant, kein Strict-Parser)
    //    -> Nur minimal prüfen, damit Framer-Widget-Format akzeptiert wird.
    const domain = (typeof req.headers.get("host") === "string" ? req.headers.get("host")! : "").toLowerCase();
    if (!message.toLowerCase().startsWith(`${domain} wants you to sign in`.toLowerCase())) {
      // Wenn du domain strikt brauchst, vergleiche hier gegen erwartete Domain(en)
      // return withCors(req, NextResponse.json({ ok:false, error:"Domain mismatch" }, { status:400 }));
    }
    if (!message.includes(`Nonce: ${nonce}`)) {
      return withCors(req, NextResponse.json({ ok:false, error:"Nonce mismatch" }, { status:400 }));
    }

    // 3) Session setzen & Nonce löschen
    const res = NextResponse.json({ ok: true, address: recovered });
    res.cookies.set("tc_session", "1", {
      httpOnly: true,
      sameSite: "none",
      secure: true,
      path: "/",
      maxAge: 60 * 60 * 24 * 7,
    });
    res.cookies.set("tc_nonce", "", { httpOnly: true, sameSite:"none", secure:true, path:"/", maxAge:0 });
    return withCors(req, res);
  } catch (e:any) {
    return withCors(req, NextResponse.json({ ok:false, error:"Verify failed" }, { status:500 }));
  }
}
