import { cert, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

import { logError, logInfo, logWarn, opaqueRef } from "./logger";

export type Role = "editor" | "viewer";

export type BotClaim = {
  botId: string;
  boardId: string;
  role: Role;
  ownerUid: string;
};

export type Identity = {
  uid: string | null;
  email: string | null;
  bot?: BotClaim;
};

export type BotPolicy = "none" | "read" | "write";

export const DEFAULT_BOT_POLICY: BotPolicy = "write";

export type Visibility = "private" | "team" | "link";
export type TeamRole = "admin" | "editor" | "viewer";

const TEAM_ID = "chats-team";

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
  title?: string;
  visibility?: Visibility;
  editors?: string[];
  viewers?: string[];
  botPolicy?: BotPolicy;
  archived?: boolean;
  type?: "personal" | "team";
  teamId?: string;
  readPolicy?: "public" | "members";
  writePolicy?: "everyone" | "whitelist" | "owner";
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

function extractBotClaim(
  decoded: Record<string, unknown>,
): BotClaim | undefined {
  if (decoded.bot !== true) {
    return undefined;
  }
  const { botId, boardId, role, ownerUid } = decoded;
  if (
    typeof botId === "string" &&
    typeof boardId === "string" &&
    typeof ownerUid === "string" &&
    (role === "editor" || role === "viewer")
  ) {
    return { botId, boardId, role, ownerUid };
  }
  return undefined;
}

export async function resolveIdentity(token?: string): Promise<Identity> {
  if (!token) {
    logWarn("firebase.socket_identity.missing_token");
    return ANONYMOUS;
  }
  try {
    const decoded = await auth.verifyIdToken(token);
    const bot = extractBotClaim(decoded as Record<string, unknown>);
    logInfo("firebase.socket_identity.verified", {
      subjectRef: opaqueRef(decoded.uid),
      bot: bot ? bot.botId : undefined,
    });
    return {
      uid: decoded.uid,
      email: decoded.email ?? null,
      ...(bot ? { bot } : {}),
    };
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

const ACL_CACHE_TTL_MS = 10 * 60_000;

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
    logWarn("firestore.board.missing", { boardId: roomId });
    const value: CachedAcl = { board: null, team: null };
    aclCache.set(roomId, { value, expiresAt: Date.now() + ACL_CACHE_TTL_MS });
    return value;
  }

  const board = boardSnap.data() as BoardDoc;
  logInfo("firestore.board.loaded", {
    boardId: roomId,
    visibility: board.visibility ?? "legacy",
  });

  let team: TeamDoc | null = null;
  const needsTeam = board.visibility === "team" || board.teamId != null;
  if (needsTeam) {
    try {
      const teamSnap = await db.collection("teams").doc(TEAM_ID).get();
      team = teamSnap.exists ? (teamSnap.data() as TeamDoc) : null;
      logInfo("firestore.team.loaded", {
        boardId: roomId,
        exists: teamSnap.exists,
      });
    } catch (error) {
      logError("firestore.team.load_failed", error, { boardId: roomId });
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

// `botPolicy` only narrows a bot's access further per board; it never grants.
function capByBotPolicy(access: Access, botPolicy: BotPolicy): Access {
  if (botPolicy === "none") {
    return { canRead: false, canWrite: false };
  }
  if (botPolicy === "read") {
    return { canRead: access.canRead, canWrite: false };
  }
  return access;
}

function inList(list: string[] | undefined, email: string | null): boolean {
  return !!email && !!list?.includes(email);
}

function teamRoleOf(
  team: TeamDoc | null,
  email: string | null,
): TeamRole | null {
  if (inList(team?.admins, email)) {
    return "admin";
  }
  if (inList(team?.editorEmails, email)) {
    return "editor";
  }
  if (inList(team?.viewerEmails, email)) {
    return "viewer";
  }
  return null;
}

function legacyAccess(
  identity: Identity,
  board: BoardDoc,
  team: TeamDoc | null,
): Access {
  const { uid, email } = identity;
  const isOwner = !!uid && uid === board.ownerUid;
  const isWhitelisted = inList(board.editors, email);
  const role = board.teamId ? teamRoleOf(team, email) : null;
  const teamEditor = role === "admin" || role === "editor";
  const teamMember = role !== null;
  return {
    canRead:
      board.readPolicy === "public" || isOwner || isWhitelisted || teamMember,
    canWrite:
      board.writePolicy === "everyone" ||
      isOwner ||
      (board.writePolicy === "whitelist" && isWhitelisted) ||
      (board.writePolicy !== "owner" && teamEditor),
  };
}

function evaluate(identity: Identity, acl: CachedAcl, asBot: boolean): Access {
  const { board, team } = acl;

  // A bot proves its scope with a verified custom claim: access derives from the
  // claimed role (not the owner's full ACL) and is still capped by botPolicy.
  if (identity.bot) {
    if (!board) {
      return { canRead: false, canWrite: false };
    }
    const claimAccess: Access = {
      canRead: true,
      canWrite: identity.bot.role === "editor",
    };
    return capByBotPolicy(claimAccess, board.botPolicy ?? DEFAULT_BOT_POLICY);
  }

  // A missing board doc means a legacy `#room=` share (secured by link secrecy)
  // for humans, but a bot must never touch a board that has no ACL document.
  if (!board) {
    return asBot
      ? { canRead: false, canWrite: false }
      : { canRead: true, canWrite: true };
  }

  const { uid, email } = identity;
  const isOwner = !!uid && uid === board.ownerUid;

  let access: Access;
  if (board.visibility === undefined) {
    access = legacyAccess(identity, board, team);
  } else {
    const role = teamRoleOf(team, email);
    const teamEditor = role === "admin" || role === "editor";
    const teamMember = role !== null;
    const invitedEditor = inList(board.editors, email);
    const invitedViewer = inList(board.viewers, email);
    access = {
      canRead:
        isOwner ||
        board.visibility === "link" ||
        (board.visibility === "team" && teamMember) ||
        invitedEditor ||
        invitedViewer,
      canWrite:
        isOwner || (board.visibility === "team" && teamEditor) || invitedEditor,
    };
  }

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
    if (identity.bot && identity.bot.boardId !== roomId) {
      logWarn("acl.bot_board_mismatch", {
        boardId: roomId,
        claimBoardId: identity.bot.boardId,
        botId: identity.bot.botId,
      });
      return { canRead: false, canWrite: false };
    }
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
