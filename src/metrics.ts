// Prometheus exposition for the collab room, without a client library: the
// numbers are few and all live in this process (socket.io rooms are in memory).
// Served on its own port (METRICS_PORT, default 9464) so it never goes through
// the public proxy and never shares the app port with the WebSocket traffic.
import http from "http";

export type JoinResult = "ok" | "denied" | "error";
export type BroadcastKind = "scene" | "cursor";

const joins: Record<JoinResult, number> = { ok: 0, denied: 0, error: 0 };
const broadcasts: Record<BroadcastKind, number> = { scene: 0, cursor: 0 };

export const countJoin = (result: JoinResult): void => {
  joins[result] += 1;
};

export const countBroadcast = (kind: BroadcastKind): void => {
  broadcasts[kind] += 1;
};

export const resetCountersForTest = (): void => {
  (Object.keys(joins) as JoinResult[]).forEach((key) => (joins[key] = 0));
  (Object.keys(broadcasts) as BroadcastKind[]).forEach(
    (key) => (broadcasts[key] = 0),
  );
};

export type BoardOccupancy = { humans: number; bots: number };

// socket.io keeps one private room per socket (keyed by its id) and this
// server adds `follow@<socketId>` rooms for "follow user"; neither is a board.
export const boardOccupancy = (
  rooms: ReadonlyMap<string, ReadonlySet<string>>,
  socketIds: ReadonlyMap<string, unknown>,
  isBot: (socketId: string) => boolean,
): BoardOccupancy[] => {
  const result: BoardOccupancy[] = [];
  rooms.forEach((members, roomId) => {
    if (socketIds.has(roomId) || roomId.startsWith("follow@")) {
      return;
    }
    let humans = 0;
    let bots = 0;
    members.forEach((socketId) => {
      if (isBot(socketId)) {
        bots += 1;
      } else {
        humans += 1;
      }
    });
    if (humans + bots > 0) {
      result.push({ humans, bots });
    }
  });
  return result;
};

export const renderMetrics = (
  boards: readonly BoardOccupancy[],
  connectedSockets: number,
): string => {
  const humans = boards.reduce((sum, board) => sum + board.humans, 0);
  const bots = boards.reduce((sum, board) => sum + board.bots, 0);
  const largest = boards.reduce(
    (max, board) => Math.max(max, board.humans + board.bots),
    0,
  );
  const lines = [
    "# HELP excalidraw_room_connected_sockets Engine.io clients connected, including ones that never joined a board (probes, idle tabs).",
    "# TYPE excalidraw_room_connected_sockets gauge",
    `excalidraw_room_connected_sockets ${connectedSockets}`,
    "# HELP excalidraw_room_boards_open Boards with at least one participant joined right now.",
    "# TYPE excalidraw_room_boards_open gauge",
    `excalidraw_room_boards_open ${boards.length}`,
    "# HELP excalidraw_room_participants Sockets joined to a board, by kind.",
    "# TYPE excalidraw_room_participants gauge",
    `excalidraw_room_participants{kind="human"} ${humans}`,
    `excalidraw_room_participants{kind="bot"} ${bots}`,
    "# HELP excalidraw_room_largest_board_participants Participants on the busiest board right now.",
    "# TYPE excalidraw_room_largest_board_participants gauge",
    `excalidraw_room_largest_board_participants ${largest}`,
    "# HELP excalidraw_room_joins_total Board join attempts, by outcome.",
    "# TYPE excalidraw_room_joins_total counter",
    ...(Object.keys(joins) as JoinResult[]).map(
      (key) => `excalidraw_room_joins_total{result="${key}"} ${joins[key]}`,
    ),
    "# HELP excalidraw_room_broadcasts_total Messages relayed to a board: scene = element changes from editors, cursor = pointer/presence updates.",
    "# TYPE excalidraw_room_broadcasts_total counter",
    ...(Object.keys(broadcasts) as BroadcastKind[]).map(
      (key) =>
        `excalidraw_room_broadcasts_total{kind="${key}"} ${broadcasts[key]}`,
    ),
  ];
  return `${lines.join("\n")}\n`;
};

export const startMetricsServer = (
  port: number,
  collect: () => string,
): http.Server | null => {
  if (!Number.isFinite(port) || port <= 0) {
    return null;
  }
  const server = http.createServer((req, res) => {
    if (req.method !== "GET" || (req.url ?? "").split("?")[0] !== "/metrics") {
      res.statusCode = 404;
      res.end();
      return;
    }
    res.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
    res.end(collect());
  });
  server.listen(port);
  return server;
};
