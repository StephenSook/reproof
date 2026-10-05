const DEFAULT_ORIGIN = "http://127.0.0.1:8765";

export function doorOrigin(): string {
  return (process.env.REPROOF_DOOR_ORIGIN ?? DEFAULT_ORIGIN).replace(/\/$/, "");
}

function forwardedHeaders(request: Request): Headers {
  const headers = new Headers();
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const cookie = request.headers.get("cookie");
  if (cookie) headers.set("cookie", cookie);
  const vercelIp = request.headers.get("x-vercel-forwarded-for");
  if (vercelIp) headers.set("x-vercel-forwarded-for", vercelIp);
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) headers.set("x-forwarded-for", forwarded);
  return headers;
}

export async function proxyDoor(request: Request, path: "/api/triage" | "/api/health"): Promise<Response> {
  let upstream: Response;
  try {
    upstream = await fetch(`${doorOrigin()}${path}`, {
      method: request.method,
      headers: forwardedHeaders(request),
      body: request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer(),
      cache: "no-store",
    });
  } catch {
    return Response.json({ error: "The triage service is not running." }, { status: 502 });
  }

  const headers = new Headers();
  const contentType = upstream.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  headers.set("cache-control", "no-store");
  const cookies = typeof upstream.headers.getSetCookie === "function" ? upstream.headers.getSetCookie() : [];
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return new Response(upstream.body, { status: upstream.status, headers });
}
