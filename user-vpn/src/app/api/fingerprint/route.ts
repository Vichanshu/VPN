import { observeServerNetwork } from "@/utils/server-network";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const network = await observeServerNetwork(request, true);
  return Response.json(network, { headers: { "cache-control": "no-store" } });
}
