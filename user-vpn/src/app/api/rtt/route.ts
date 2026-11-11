export const dynamic = "force-dynamic";

/** Minimal echo for client application-layer RTT sampling. */
export function GET() {
  return new Response("ok", { headers: { "cache-control": "no-store", "content-type": "text/plain" } });
}
