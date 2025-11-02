// wallet/pay.ts
"use client";

import walletService from "./walletService.ts";

// Erlaubte Chains
const ALLOWED_CHAINS = new Set<number>([1, 11155111]); // mainnet + sepolia

type SendOptions = {
  to: `0x${string}`;
  /** ETH als String, z.B. "0.01" */
  valueEth: string;
  /** Optional: explizite Chain-ID, sonst aus Wallet-Zustand */
  chainId?: number;
};

type SendResultOk = { ok: true; hash: `0x${string}` };
type SendResultCancel = { ok: false; canceled: true; error: string };
type SendResultErr = { ok: false; error: string };
export type SendResult = SendResultOk | SendResultCancel | SendResultErr;

export async function sendEth(options: SendOptions): Promise<SendResult> {
  const { to, valueEth } = options;

  // 1) Wallet-Status prüfen
  const s = walletService.getState();
  if (!s.connected || !s.address) {
    return { ok: false, error: "Wallet not connected" };
  }

  // 2) Chain prüfen
  const chainId = (options.chainId ?? s.chainId) ?? 1;
  if (!ALLOWED_CHAINS.has(chainId)) {
    return { ok: false, error: `Chain ${chainId} is not allowed` };
  }

  // 3) viem lazy laden
  const viem = await import("viem");
  const viemChains = await import("viem/chains");

  // 4) Provider holen
  const provider = (globalThis as any).ethereum;
  if (!provider) {
    return { ok: false, error: "No injected provider (window.ethereum)" };
  }

  // 5) Client erstellen
  const chain = pickChain(chainId, viemChains);
  const client = viem.createWalletClient({
    account: s.address as `0x${string}`,
    chain,
    transport: viem.custom(provider),
  });

  // 6) Senden
  try {
    const hash = await client.sendTransaction({
      to,
      value: viem.parseEther(valueEth),
    });
    return { ok: true, hash };
  } catch (e: any) {
    if (e?.code === 4001) {
      return { ok: false, canceled: true, error: "User rejected" };
    }
    return { ok: false, error: e?.message ?? "send failed" };
  }
}

function pickChain(
  id: number,
  chains: typeof import("viem/chains")
): any {
  if (id === chains.mainnet.id) return chains.mainnet;
  if (id === chains.sepolia.id) return chains.sepolia;
  // Minimal-Fallback, wenn wir eine andere Chain zulassen würden
  return {
    id,
    name: `chain-${id}`,
    nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [] as string[] } },
  } as const;
}

// Optionaler Hard-Fallback ohne viem
export async function sendEthFallback(options: SendOptions): Promise<SendResult> {
  const { to, valueEth } = options;
  const s = walletService.getState();
  if (!s.connected || !s.address) return { ok: false, error: "Wallet not connected" };
  const provider = (globalThis as any).ethereum;
  if (!provider) return { ok: false, error: "No injected provider" };

  const wei = BigInt(Math.floor(Number(valueEth) * 1e18)).toString(16);
  const tx = { from: s.address, to, value: `0x${wei}` as const };
  try {
    const hash = await provider.request({ method: "eth_sendTransaction", params: [tx] });
    return { ok: true, hash };
  } catch (e: any) {
    if (e?.code === 4001) return { ok: false, canceled: true, error: "User rejected" };
    return { ok: false, error: e?.message ?? "send failed" };
  }
}
