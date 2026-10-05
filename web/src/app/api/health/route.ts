import { proxyDoor } from "@/lib/proxy";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export function GET(request: Request): Promise<Response> {
  return proxyDoor(request, "/api/health");
}
