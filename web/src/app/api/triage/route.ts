import { proxyDoor } from "@/lib/proxy";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function POST(request: Request): Promise<Response> {
  return proxyDoor(request, "/api/triage");
}
