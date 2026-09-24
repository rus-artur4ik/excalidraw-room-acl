import http from "http";
import { AddressInfo } from "net";

import { afterEach, describe, expect, it } from "vitest";

import {
  boardOccupancy,
  countBroadcast,
  countJoin,
  renderMetrics,
  resetCountersForTest,
  startMetricsServer,
} from "../metrics";

const get = (port: number, path: string) =>
  new Promise<{ status: number; body: string }>((resolve, reject) => {
    http
      .get({ host: "127.0.0.1", port, path }, (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      })
      .on("error", reject);
  });

describe("boardOccupancy", () => {
  it("skips per-socket and follow rooms and splits humans from bots", () => {
    const sockets = new Map<string, unknown>([
      ["s1", {}],
      ["s2", {}],
      ["bot1", {}],
    ]);
    const rooms = new Map<string, Set<string>>([
      ["s1", new Set(["s1"])],
      ["s2", new Set(["s2"])],
      ["bot1", new Set(["bot1"])],
      ["follow@s1", new Set(["s2"])],
      ["board-a", new Set(["s1", "s2", "bot1"])],
      ["board-b", new Set(["s2"])],
      ["board-empty", new Set<string>()],
    ]);
    const result = boardOccupancy(rooms, sockets, (id) => id.startsWith("bot"));
    expect(result).toEqual([
      { humans: 2, bots: 1 },
      { humans: 1, bots: 0 },
    ]);
  });
});

describe("renderMetrics", () => {
  afterEach(() => resetCountersForTest());

  it("renders gauges and counters in text exposition format", () => {
    countJoin("ok");
    countJoin("ok");
    countJoin("denied");
    countBroadcast("scene");
    const text = renderMetrics(
      [
        { humans: 2, bots: 1 },
        { humans: 1, bots: 0 },
      ],
      5,
    );
    expect(text).toContain("excalidraw_room_connected_sockets 5\n");
    expect(text).toContain("excalidraw_room_boards_open 2\n");
    expect(text).toContain('excalidraw_room_participants{kind="human"} 3\n');
    expect(text).toContain('excalidraw_room_participants{kind="bot"} 1\n');
    expect(text).toContain("excalidraw_room_largest_board_participants 3\n");
    expect(text).toContain('excalidraw_room_joins_total{result="ok"} 2\n');
    expect(text).toContain('excalidraw_room_joins_total{result="denied"} 1\n');
    expect(text).toContain('excalidraw_room_joins_total{result="error"} 0\n');
    expect(text).toContain(
      'excalidraw_room_broadcasts_total{kind="scene"} 1\n',
    );
    expect(text).toContain(
      'excalidraw_room_broadcasts_total{kind="cursor"} 0\n',
    );
    expect(text.endsWith("\n")).toBe(true);
  });

  it("reports zeros when nobody is on a board", () => {
    const text = renderMetrics([], 0);
    expect(text).toContain("excalidraw_room_boards_open 0\n");
    expect(text).toContain("excalidraw_room_largest_board_participants 0\n");
  });
});

describe("startMetricsServer", () => {
  it("is disabled by a zero port", () => {
    expect(startMetricsServer(0, () => "")).toBeNull();
  });

  it("serves /metrics and 404s everything else", async () => {
    const live = http.createServer();
    await new Promise<void>((resolve) => live.listen(0, resolve));
    const port = (live.address() as AddressInfo).port;
    live.close();
    const real = startMetricsServer(port, () => "x 1\n")!;
    await new Promise((resolve) => real.once("listening", resolve));
    try {
      const ok = await get(port, "/metrics");
      expect(ok.status).toBe(200);
      expect(ok.body).toBe("x 1\n");
      const miss = await get(port, "/");
      expect(miss.status).toBe(404);
    } finally {
      real.close();
    }
  });
});
