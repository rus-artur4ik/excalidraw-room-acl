import { cert, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

import { logError, logInfo, logWarn, opaqueRef } from "./logger";

export type Identity = {
  uid: string | null;
  email: string | null;
};

export type Role = "editor" | "viewer";

export type BotPolicy = "none" | "read" | "write";

export const DEFAULT_BOT_POLICY: BotPolicy = "write";

export type Access = {
  canRead: boolean;
  canWrite: boolean;
};

export type SocketData = {
  identity: Identity;
  roles: Map<string, Role>;
  asBot: boolean;
};

type BoardDoc = {
  ownerUid?: string;
  ownerEmail?: string;
  type?: "personal" | "team";
  teamId?: string;
  readPolicy?: "public" | "members";
  writePolicy?: "everyone" | "whitelist" | "owner";
  editors?: string[];
  botPolicy?: BotPolicy;
};

type TeamDoc = {
  admins?: string[];
  editorEmails?: string[];
  viewerEmails?: string[];
};

export const ANONYMOUS: Identity = { uid: null, email: null };

const serviceAccountPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
if (!serviceAccountPath) {
  throw new Error(
    "Missing required environment variable: GOOGLE_APPLICATION_CREDENTIALS",
  );
}

const firebaseApp = initializeApp({
  credential: cert(serviceAccountPath),
  projectId: process.env.FIREBASE_PROJECT_ID || "excalidraw-team",
});

const auth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);
logInfo("firebase.admin.initialized", {
  projectId: process.env.FIREBASE_PROJECT_ID || "excalidraw-team",
  credentialPath: serviceAccountPath,
  credentialType: "service-account-cert",
});

export async function resolveIdentity(token?: string): Promise<Identity> {
  if (!token) {
    logWarn("firebase.socket_identity.missing_token");
    return ANONYMOUS;
  }
  try {
    const decoded = await auth.verifyIdToken(token);
    logInfo("firebase.socket_identity.verified", {
      subjectRef: opaqueRef(decoded.uid),
    });
    return { uid: decoded.uid, email: decoded.email ?? null };
  } catch (error) {
    logError("firebase.socket_identity.verify_failed", error, {
      tokenRef: opaqueRef(token),
    });
    return ANONYMOUS;
  }
}

type CachedAcl = {
  board: BoardDoc | null;
  team: TeamDoc | null;
};

const ACL_CACHE_TTL_MS = 10_000;

const aclCache = new Map<string, { value: CachedAcl; expiresAt: number }>();

class AclUnavailableError extends Error {}

async function loadAcl(roomId: string): Promise<CachedAcl> {
  const cached = aclCache.get(roomId);
  if (cached && cached.expiresAt > Date.now()) {
    logInfo("acl.cache_hit", { boardId: roomId });
    return cached.value;
  }
  logInfo("acl.cache_miss", { boardId: roomId });

  let boardSnap;
  try {
    boardSnap = await db.collection("boards").doc(roomId).get();
  } catch (error) {
    logError("firestore.board.load_failed", error, { boardId: roomId });
    throw new AclUnavailableError(`failed to load board ACL for ${roomId}`, {
      cause: error,
    });
  }

  if (!boardSnap.exists) {
    logWarn("firestore.board.missing_defaults_to_open", { boardId: roomId });
    const value: CachedAcl = { board: null, team: null };
    aclCache.set(roomId, { value, expiresAt: Date.now() + ACL_CACHE_TTL_MS });
    return value;
  }

  const board = boardSnap.data() as BoardDoc;
  logInfo("firestore.board.loaded", {
    boardId: roomId,
    boardType: board.type,
    readPolicy: board.readPolicy,
    writePolicy: board.writePolicy,
    hasTeam: !!board.teamId,
  });

  let team: TeamDoc | null = null;
  if (board.teamId) {
    try {
      const teamSnap = await db.collection("teams").doc(board.teamId).get();
      team = teamSnap.exists ? (teamSnap.data() as TeamDoc) : null;
      logInfo("firestore.team.loaded", {
        boardId: roomId,
        teamRef: opaqueRef(board.teamId),
        exists: teamSnap.exists,
      });
    } catch (error) {
      logError("firestore.team.load_failed", error, {
        boardId: roomId,
        teamRef: opaqueRef(board.teamId),
      });
      throw new AclUnavailableError(`failed to load team ACL for ${roomId}`, {
        cause: error,
      });
    }
  }

  const value: CachedAcl = { board, team };
  aclCache.set(roomId, { value, expiresAt: Date.now() + ACL_CACHE_TTL_MS });
  return value;
}

export function invalidateAcl(roomId: string): void {
  aclCache.delete(roomId);
  logInfo("acl.cache_invalidated", { boardId: roomId });
}

// A bot impersonates the user who minted its token, so it can never exceed that
// user's access. `botPolicy` only narrows it further per board.
function capByBotPolicy(access: Access, botPolicy: BotPolicy): Access {
  if (botPolicy === "none") {
    return { canRead: false, canWrite: false };
  }
  if (botPolicy === "read") {
    return { canRead: access.canRead, canWrite: false };
  }
  return access;
}

function evaluate(identity: Identity, acl: CachedAcl, asBot: boolean): Access {
  const { board, team } = acl;

  if (!board) {
    const open: Access = { canRead: true, canWrite: true };
    return asBot ? capByBotPolicy(open, DEFAULT_BOT_POLICY) : open;
  }

  const { uid, email } = identity;

  const isOwner = !!uid && uid === board.ownerUid;
  const isWhitelisted = !!email && !!board.editors?.includes(email);

  const teamAdmin = !!team && !!email && !!team.admins?.includes(email);
  const teamEditor =
    teamAdmin || (!!team && !!email && !!team.editorEmails?.includes(email));
  const teamMember =
    teamAdmin ||
    teamEditor ||
    (!!team && !!email && !!team.viewerEmails?.includes(email));

  const canRead =
    board.readPolicy === "public" || isOwner || isWhitelisted || teamMember;

  const canWrite =
    board.writePolicy === "everyone" ||
    isOwner ||
    teamAdmin ||
    (board.writePolicy === "whitelist" && isWhitelisted) ||
    (board.writePolicy !== "owner" && teamEditor);

  const access: Access = { canRead, canWrite };
  return asBot
    ? capByBotPolicy(access, board.botPolicy ?? DEFAULT_BOT_POLICY)
    : access;
}

export async function authorize(
  roomId: string,
  identity: Identity,
  asBot = false,
): Promise<Access> {
  try {
    const acl = await loadAcl(roomId);
    const access = evaluate(identity, acl, asBot);
    logInfo("acl.evaluated", {
      boardId: roomId,
      subjectRef: opaqueRef(identity.uid),
      asBot,
      canRead: access.canRead,
      canWrite: access.canWrite,
    });
    return access;
  } catch (error) {
    logError("acl.evaluate_failed", error, {
      boardId: roomId,
      subjectRef: opaqueRef(identity.uid),
    });
    throw error;
  }
}
