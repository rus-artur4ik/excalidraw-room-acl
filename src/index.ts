import express from "express";
import http from "http";
import { Server as SocketIO } from "socket.io";

import {
  authorize,
  invalidateAcl,
  resolveIdentity,
  ANONYMOUS,
  Identity,
  Role,
  SocketData,
} from "./accessControl";
import { logError, logInfo, logWarn, opaqueRef } from "./logger";

type Events = Record<string, (...args: any[]) => void>;

type UserToFollow = {
  socketId: string;
  username: string;
};
type OnUserFollowedPayload = {
  userToFollow: UserToFollow;
  action: "FOLLOW" | "UNFOLLOW";
};

require("dotenv").config(
  process.env.NODE_ENV !== "development"
    ? { path: ".env.production" }
    : { path: ".env.development" },
);

const app = express();
const port =
  process.env.PORT || (process.env.NODE_ENV !== "development" ? 80 : 3002); // default port to listen

app.use(express.static("public"));
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Excalidraw collaboration server is up :)");
});

const server = http.createServer(app);
let processTerminationStarted = false;

const terminateAfterLogging = (
  event: string,
  error: unknown,
  fields: Record<string, unknown> = {},
): void => {
  logError(event, error, fields);
  if (processTerminationStarted) {
    return;
  }
  processTerminationStarted = true;
  setTimeout(() => process.exit(1), 50);
};

process.on("unhandledRejection", (reason) => {
  terminateAfterLogging("process.unhandled_rejection", reason);
});

process.on("uncaughtException", (error, origin) => {
  terminateAfterLogging("process.uncaught_exception", error, { origin });
});

server.on("error", (error) => {
  logError("http.server.error", error, { port });
});

server.listen(port, () => {
  logInfo("room.started", {
    port,
    firebaseProjectId: process.env.FIREBASE_PROJECT_ID || "excalidraw-team",
    corsOrigin: process.env.CORS_ORIGIN || "*",
    credentialPath:
      process.env.GOOGLE_APPLICATION_CREDENTIALS || "<not-configured>",
    credentialType: "service-account-cert",
  });
});

try {
  const io = new SocketIO<Events, Events, Events, SocketData>(server, {
    transports: ["websocket", "polling"],
    cors: {
      allowedHeaders: ["Content-Type", "Authorization"],
      origin: process.env.CORS_ORIGIN || "*",
      credentials: true,
    },
    allowEIO3: true,
  });

  io.engine.on("connection_error", (error) => {
    logError("socket.engine.connection_error", error, {
      errorCode: error.code,
      transport: error.context?.transport,
    });
  });

  io.on("connection", (socket) => {
    const token: string | undefined = socket.handshake.auth?.token;
    const tokenRef = opaqueRef(token);
    const traceId =
      typeof socket.handshake.auth?.traceId === "string"
        ? socket.handshake.auth.traceId.slice(0, 128)
        : undefined;
    logInfo("socket.connected", {
      socketId: socket.id,
      transport: socket.conn.transport.name,
      tokenPresent: !!token,
      tokenRef,
      traceId,
    });
    io.to(`${socket.id}`).emit("init-room");
    logInfo("socket.init_room_sent", {
      socketId: socket.id,
      tokenRef,
      traceId,
    });

    const asBot = socket.handshake.auth?.asBot === true;
    const identityPromise: Promise<Identity> = resolveIdentity(token);
    const roles = new Map<string, Role>();
    socket.data = { identity: ANONYMOUS, roles, asBot };

    socket.on("join-room", async (roomID) => {
      try {
        logInfo("socket.join_room.started", {
          socketId: socket.id,
          boardId: roomID,
          tokenRef,
          traceId,
        });
        const identity = await identityPromise;
        const { canRead, canWrite } = await authorize(roomID, identity, asBot);

        if (!canRead) {
          logWarn("socket.join_room.policy_denied", {
            socketId: socket.id,
            boardId: roomID,
            subjectRef: opaqueRef(identity.uid),
            traceId,
          });
          socket.emit("access-denied", {
            roomId: roomID,
            reason: "acl-policy",
          });
          return;
        }

        const role: Role = canWrite ? "editor" : "viewer";
        socket.data.identity = identity;
        roles.set(roomID, role);

        await socket.join(roomID);
        const sockets = await io.in(roomID).fetchSockets();
        logInfo("socket.join_room.succeeded", {
          socketId: socket.id,
          boardId: roomID,
          subjectRef: opaqueRef(identity.uid),
          role,
          participantCount: sockets.length,
          traceId,
        });
        if (sockets.length <= 1) {
          io.to(`${socket.id}`).emit("first-in-room");
        } else {
          socket.broadcast.to(roomID).emit("new-user", socket.id);
        }

        io.in(roomID).emit(
          "room-user-change",
          sockets.map((roomSocket) => roomSocket.id),
        );
      } catch (error) {
        logError("socket.join_room.failed", error, {
          socketId: socket.id,
          boardId: roomID,
          tokenRef,
          traceId,
        });
        socket.emit("access-denied", {
          roomId: roomID,
          reason: "acl-unavailable",
        });
      }
    });

    socket.on(
      "server-broadcast",
      (roomID: string, encryptedData: ArrayBuffer, iv: Uint8Array) => {
        if (roles.get(roomID) !== "editor") {
          logWarn("socket.broadcast.dropped_non_editor", {
            socketId: socket.id,
            boardId: roomID,
            role: roles.get(roomID) ?? "none",
            traceId,
          });
          return;
        }
        socket.broadcast.to(roomID).emit("client-broadcast", encryptedData, iv);
      },
    );

    socket.on(
      "server-volatile-broadcast",
      (roomID: string, encryptedData: ArrayBuffer, iv: Uint8Array) => {
        if (!roles.has(roomID)) {
          logWarn("socket.volatile_broadcast.dropped_not_joined", {
            socketId: socket.id,
            boardId: roomID,
            traceId,
          });
          return;
        }
        socket.volatile.broadcast
          .to(roomID)
          .emit("client-broadcast", encryptedData, iv);
      },
    );

    socket.on("user-follow", async (payload: OnUserFollowedPayload) => {
      const roomID = `follow@${payload.userToFollow.socketId}`;

      switch (payload.action) {
        case "FOLLOW": {
          await socket.join(roomID);

          const sockets = await io.in(roomID).fetchSockets();
          const followedBy = sockets.map((socket) => socket.id);

          io.to(payload.userToFollow.socketId).emit(
            "user-follow-room-change",
            followedBy,
          );

          break;
        }
        case "UNFOLLOW": {
          await socket.leave(roomID);

          const sockets = await io.in(roomID).fetchSockets();
          const followedBy = sockets.map((socket) => socket.id);

          io.to(payload.userToFollow.socketId).emit(
            "user-follow-room-change",
            followedBy,
          );

          break;
        }
      }
    });

    socket.on("disconnecting", async () => {
      try {
        logInfo("socket.disconnecting", {
          socketId: socket.id,
          rooms: Array.from(socket.rooms),
          traceId,
        });
        for (const roomID of Array.from(socket.rooms)) {
          const otherClients = (await io.in(roomID).fetchSockets()).filter(
            (_socket) => _socket.id !== socket.id,
          );

          const isFollowRoom = roomID.startsWith("follow@");

          if (!isFollowRoom && otherClients.length > 0) {
            socket.broadcast.to(roomID).emit(
              "room-user-change",
              otherClients.map((roomSocket) => roomSocket.id),
            );
          }

          if (isFollowRoom && otherClients.length === 0) {
            const socketId = roomID.replace("follow@", "");
            io.to(socketId).emit("broadcast-unfollow");
          }
        }
      } catch (error) {
        logError("socket.disconnecting.failed", error, {
          socketId: socket.id,
          traceId,
        });
      }
    });

    socket.on("error", (error) => {
      logError("socket.error", error, { socketId: socket.id, traceId });
    });

    socket.on("disconnect", (reason) => {
      logInfo("socket.disconnected", {
        socketId: socket.id,
        reason,
        traceId,
      });
      socket.removeAllListeners();
      socket.disconnect();
    });
  });

  app.post("/internal/acl-changed/:roomId", async (req, res) => {
    const expectedSecret = process.env.INTERNAL_SECRET;
    if (!expectedSecret || req.header("x-internal-secret") !== expectedSecret) {
      logWarn("acl_change.unauthorized", { boardId: req.params.roomId });
      res.sendStatus(403);
      return;
    }

    const { roomId } = req.params;
    invalidateAcl(roomId);

    try {
      const sockets = await io.in(roomId).fetchSockets();
      for (const remote of sockets) {
        const identity = remote.data.identity ?? ANONYMOUS;

        let canRead: boolean;
        let canWrite: boolean;
        try {
          ({ canRead, canWrite } = await authorize(
            roomId,
            identity,
            remote.data.asBot === true,
          ));
        } catch (error) {
          logError("acl_change.socket_reevaluation_failed", error, {
            boardId: roomId,
            socketId: remote.id,
            subjectRef: opaqueRef(identity.uid),
          });
          // Keep current access during a transient ACL-load failure.
          continue;
        }

        if (!canRead) {
          logWarn("acl_change.socket_access_revoked", {
            boardId: roomId,
            socketId: remote.id,
            subjectRef: opaqueRef(identity.uid),
          });
          remote.emit("access-denied", {
            roomId,
            reason: "acl-policy-changed",
          });
          remote.disconnect(true);
          continue;
        }

        remote.data.roles?.set(roomId, canWrite ? "editor" : "viewer");
      }

      logInfo("acl_change.completed", {
        boardId: roomId,
        socketCount: sockets.length,
      });
      res.sendStatus(204);
    } catch (error) {
      logError("acl_change.failed", error, { boardId: roomId });
      res.sendStatus(500);
    }
  });
} catch (error) {
  logError("room.initialization_failed", error);
  throw error;
}
