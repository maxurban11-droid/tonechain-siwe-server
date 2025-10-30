// utils/siwe.ts
import { verifyMessage } from "ethers";

export type VerifyResult = { ok: boolean; address?: string; error?: string };

// Tolerant verification for personal_sign messages (EIP-191)
export async function verifyPersonalSign(message: string, signature: string): Promise<VerifyResult> {
  try {
    const address = await verifyMessage(message, signature);
    return { ok: true, address };
  } catch (e:any) {
    return { ok: false, error: "Invalid signature" };
  }
}
