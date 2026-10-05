import { afterEach, describe, expect, it, vi } from "vitest";
import { POST } from "../src/app/api/triage/route";
import evaluation from "../src/content/arvo10.json";
import { isLimitPayload, missingSteps, parseNdjson, takeLines, type DoorEvent } from "../src/lib/events";
import { NOT_IN_RECORDED_SUMMARY, recordedView } from "../src/lib/recorded";

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.REPROOF_DOOR_ORIGIN;
});

describe("triage stream", () => {
  it("splits complete NDJSON lines and names every missing step", () => {
    expect(takeLines('{"type":"step"}\n{"type":')).toEqual({
      lines: ['{"type":"step"}'],
      rest: '{"type":',
    });
    const events = parseNdjson(
      [
        '{"type":"step","step":{"step":"claim","kind":null,"payload":{}}}',
        '{"type":"step","step":{"step":"sandbox","kind":"vul","payload":{}}}',
        '{"type":"result","result":{"verdict":"NEEDS_INFO"}}',
      ].join("\n"),
    );
    expect(missingSteps(events as DoorEvent[])).toEqual([
      "sandbox:fix",
      "crash",
      "duplicates",
      "verdict",
    ]);
    expect(
      isLimitPayload(429, {
        error: "This address has reached the hourly triage limit.",
        limits: { per_ip_per_hour: 8 },
      }),
    ).toBe(true);
    expect(isLimitPayload(200, { verdict: "REPRODUCED", error: "no" })).toBe(false);
  });

  it("pipes the Python response and does not add a credential header", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response('{"type":"result","result":{"verdict":"NEEDS_INFO","card":null}}\n', {
          status: 200,
          headers: {
            "content-type": "application/x-ndjson; charset=utf-8",
            "set-cookie": "reproof_visitor=abc; HttpOnly; Path=/",
          },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const response = await POST(
      new Request("http://judge.local/api/triage", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: "reproof_visitor=abc" },
        body: '{"arvo_id":1}',
      }),
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("NEEDS_INFO");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://127.0.0.1:8765/api/triage");
    const headers = new Headers(init.headers);
    expect(headers.get("cookie")).toBe("reproof_visitor=abc");
    expect(headers.get("authorization")).toBeNull();
    expect([...headers.keys()].some((key) => key.toLowerCase().includes("nebius"))).toBe(false);
  });

  it("returns the upstream refusal without turning it into a verdict", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json(
          { error: "This address has reached the hourly triage limit.", limits: { per_ip_per_hour: 8 } },
          { status: 429 },
        ),
      ),
    );
    const response = await POST(
      new Request("http://judge.local/api/triage", {
        method: "POST",
        body: '{"arvo_id":42530604}',
      }),
    );
    expect(response.status).toBe(429);
    const payload = (await response.json()) as { error: string; verdict?: string };
    expect(isLimitPayload(response.status, payload)).toBe(true);
    expect(payload.verdict).toBeUndefined();
  });

  it("says the service is down when the door cannot be reached", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("connect failed");
      }),
    );
    const response = await POST(new Request("http://judge.local/api/triage", { method: "POST", body: "{}" }));
    expect(response.status).toBe(502);
    const payload = (await response.json()) as { error: string; verdict?: string };
    expect(payload.error).toBe("The triage service is not running.");
    expect(payload.verdict).toBeUndefined();
  });
});

describe("recorded rows", () => {
  it("uses the saved operation ids and does not invent excluded ids", () => {
    const first = recordedView(evaluation.tasks[0]);
    expect(first.source).toBe("RECORDED");
    expect(first.card).toBeNull();
    expect(first.steps[0]?.payload.model).toBe(NOT_IN_RECORDED_SUMMARY);
    expect(first.steps[0]?.payload.bug_class).toBe(NOT_IN_RECORDED_SUMMARY);
    expect(first.steps[1]).toMatchObject({
      step: "sandbox",
      kind: "vul",
      payload: { operation_uuid: "01a10d76-4c5f-7726-8825-c7b18b1ff5d8", wall_seconds: null },
    });
    expect(first.steps[2]).toMatchObject({
      step: "sandbox",
      kind: "fix",
      payload: { operation_uuid: "01a10d76-4d3b-76a4-b69f-3f853d63a4ca" },
    });
    expect(first.steps[4]?.payload.excluded_osv_ids).toBeNull();
    expect(first.steps[4]?.payload.excluded_note).toContain("not in the recorded summary");

    const duplicate = recordedView(evaluation.tasks[3]);
    expect(duplicate.verdict).toBe("DUPLICATE");
    expect(duplicate.steps[4]?.payload.candidates).toEqual([{ id: "OSV-2022-147" }]);
  });
});
