import debug from "debug";
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

type Events = Record<string, (...args: any[]) => void>;

type UserToFollow = {
  socketId: string;
  username: string;
};
type OnUserFollowedPayload = {
  userToFollow: UserToFollow;
  action: "FOLLOW" | "UNFOLLOW";
};

const serverDebug = debug("server");
const ioDebug = debug("io");
const socketDebug = debug("socket");

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

server.listen(port, () => {
  serverDebug(`listening on port: ${port}`);
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

  io.on("connection", (socket) => {
    ioDebug("connection established!");
    io.to(`${socket.id}`).emit("init-room");

    const token: string | undefined = socket.handshake.auth?.token;
    const identityPromise: Promise<Identity> = resolveIdentity(token);
    const roles = new Map<string, Role>();
    socket.data = { identity: ANONYMOUS, roles };

    socket.on("join-room", async (roomID) => {
      socketDebug(`${socket.id} attempts to join ${roomID}`);
      const identity = await identityPromise;

      let canRead: boolean;
      let canWrite: boolean;
      try {
        ({ canRead, canWrite } = await authorize(roomID, identity));
      } catch (error) {
        socketDebug(`${socket.id} denied access to ${roomID}: ${error}`);
        socket.emit("access-denied", { roomId: roomID });
        return;
      }

      if (!canRead) {
        socketDebug(`${socket.id} denied access to ${roomID}`);
        socket.emit("access-denied", { roomId: roomID });
        return;
      }

      const role: Role = canWrite ? "editor" : "viewer";
      socket.data.identity = identity;
      roles.set(roomID, role);

      socketDebug(`${socket.id} has joined ${roomID} as ${role}`);
      await socket.join(roomID);
      const sockets = await io.in(roomID).fetchSockets();
      if (sockets.length <= 1) {
        io.to(`${socket.id}`).emit("first-in-room");
      } else {
        socketDebug(`${socket.id} new-user emitted to room ${roomID}`);
        socket.broadcast.to(roomID).emit("new-user", socket.id);
      }

      io.in(roomID).emit(
        "room-user-change",
        sockets.map((socket) => socket.id),
      );
    });

    socket.on(
      "server-broadcast",
      (roomID: string, encryptedData: ArrayBuffer, iv: Uint8Array) => {
        if (roles.get(roomID) !== "editor") {
          socketDebug(`${socket.id} dropped non-editor update to ${roomID}`);
          return;
        }
        socketDebug(`${socket.id} sends update to ${roomID}`);
        socket.broadcast.to(roomID).emit("client-broadcast", encryptedData, iv);
      },
    );

    socket.on(
      "server-volatile-broadcast",
      (roomID: string, encryptedData: ArrayBuffer, iv: Uint8Array) => {
        if (!roles.has(roomID)) {
          return;
        }
        socketDebug(`${socket.id} sends volatile update to ${roomID}`);
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
      socketDebug(`${socket.id} has disconnected`);
      for (const roomID of Array.from(socket.rooms)) {
        const otherClients = (await io.in(roomID).fetchSockets()).filter(
          (_socket) => _socket.id !== socket.id,
        );

        const isFollowRoom = roomID.startsWith("follow@");

        if (!isFollowRoom && otherClients.length > 0) {
          socket.broadcast.to(roomID).emit(
            "room-user-change",
            otherClients.map((socket) => socket.id),
          );
        }

        if (isFollowRoom && otherClients.length === 0) {
          const socketId = roomID.replace("follow@", "");
          io.to(socketId).emit("broadcast-unfollow");
        }
      }
    });

    socket.on("disconnect", () => {
      socket.removeAllListeners();
      socket.disconnect();
    });
  });

  app.post("/internal/acl-changed/:roomId", async (req, res) => {
    const expectedSecret = process.env.INTERNAL_SECRET;
    if (!expectedSecret || req.header("x-internal-secret") !== expectedSecret) {
      res.sendStatus(403);
      return;
    }

    const { roomId } = req.params;
    invalidateAcl(roomId);

    const sockets = await io.in(roomId).fetchSockets();
    for (const remote of sockets) {
      const identity = remote.data.identity ?? ANONYMOUS;

      let canRead: boolean;
      let canWrite: boolean;
      try {
        ({ canRead, canWrite } = await authorize(roomId, identity));
      } catch {
        // Transient ACL-load failure: keep current access rather than disconnecting an already-authorized user.
        continue;
      }

      if (!canRead) {
        remote.emit("access-denied", { roomId });
        remote.disconnect(true);
        continue;
      }

      remote.data.roles?.set(roomId, canWrite ? "editor" : "viewer");
    }

    res.sendStatus(204);
  });
} catch (error) {
  console.error(error);
}
