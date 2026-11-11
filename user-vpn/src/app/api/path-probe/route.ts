import { createProbeResponse, observeServerNetwork } from "@/utils/server-network";
import type { PathProbeKind } from "@/utils/network";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const kind: PathProbeKind = url.searchParams.get("kind") === "ipv6" ? "ipv6" : "ipv4";
  const network = await observeServerNetwork(request);
  const response = Response.json(createProbeResponse(kind, network), {
    headers: { "cache-control": "no-store" },
  });
  const allowedOrigin = process.env.RESEARCH_APP_ORIGIN;
  const requestOrigin = request.headers.get("origin");
  if (allowedOrigin && requestOrigin === allowedOrigin) {
    response.headers.set("access-control-allow-origin", allowedOrigin);
    response.headers.set("vary", "origin");
  }
  return response;
}

export async function OPTIONS(request: Request) {
  const allowedOrigin = process.env.RESEARCH_APP_ORIGIN;
  const requestOrigin = request.headers.get("origin");
  return new Response(null, {
    status: 204,
    headers: requestOrigin && allowedOrigin === requestOrigin ? {
      "access-control-allow-origin": allowedOrigin,
      "access-control-allow-methods": "GET, OPTIONS",
      "access-control-allow-headers": "content-type",
      "access-control-max-age": "86400",
      "vary": "origin",
    } : {},
  });
}
