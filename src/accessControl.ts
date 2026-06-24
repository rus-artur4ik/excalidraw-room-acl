import debug from "debug";
import { initializeApp, applicationDefault } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";

const aclDebug = debug("acl");

export type Identity = {
  uid: string | null;
  email: string | null;
};

export type Role = "editor" | "viewer";

export type Access = {
  canRead: boolean;
  canWrite: boolean;
};

export type SocketData = {
  identity: Identity;
  roles: Map<string, Role>;
};

type BoardDoc = {
  ownerUid?: string;
  ownerEmail?: string;
  type?: "personal" | "team";
  teamId?: string;
  readPolicy?: "public" | "members";
  writePolicy?: "everyone" | "whitelist" | "owner";
  editors?: string[];
};

type TeamDoc = {
  admins?: string[];
  editorEmails?: string[];
  viewerEmails?: string[];
};

export const ANONYMOUS: Identity = { uid: null, email: null };

const firebaseApp = initializeApp({
  credential: applicationDefault(),
  projectId: process.env.FIREBASE_PROJECT_ID || "excalidraw-team",
});

const auth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);

export async function resolveIdentity(token?: string): Promise<Identity> {
  if (!token) {
    return ANONYMOUS;
  }
  try {
    const decoded = await auth.verifyIdToken(token);
    return { uid: decoded.uid, email: decoded.email ?? null };
  } catch (error) {
    aclDebug(`token verification failed, treating as anonymous: ${error}`);
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
    return cached.value;
  }

  let boardSnap;
  try {
    boardSnap = await db.collection("boards").doc(roomId).get();
  } catch (error) {
    aclDebug(`failed to read board ${roomId} from Firestore: ${error}`);
    throw new AclUnavailableError();
  }

  if (!boardSnap.exists) {
    const value: CachedAcl = { board: null, team: null };
    aclCache.set(roomId, { value, expiresAt: Date.now() + ACL_CACHE_TTL_MS });
    return value;
  }

  const board = boardSnap.data() as BoardDoc;

  let team: TeamDoc | null = null;
  if (board.teamId) {
    try {
      const teamSnap = await db.collection("teams").doc(board.teamId).get();
      team = teamSnap.exists ? (teamSnap.data() as TeamDoc) : null;
    } catch (error) {
      aclDebug(`failed to read team ${board.teamId} from Firestore: ${error}`);
      throw new AclUnavailableError();
    }
  }

  const value: CachedAcl = { board, team };
  aclCache.set(roomId, { value, expiresAt: Date.now() + ACL_CACHE_TTL_MS });
  return value;
}

export function invalidateAcl(roomId: string): void {
  aclCache.delete(roomId);
}

function evaluate(identity: Identity, acl: CachedAcl): Access {
  const { board, team } = acl;

  if (!board) {
    return { canRead: true, canWrite: true };
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

  return { canRead, canWrite };
}

export async function authorize(
  roomId: string,
  identity: Identity,
): Promise<Access> {
  const acl = await loadAcl(roomId);
  return evaluate(identity, acl);
}
