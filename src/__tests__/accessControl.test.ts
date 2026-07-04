import { beforeEach, describe, expect, it, vi } from "vitest";
import type { BoardDoc, Identity, TeamDoc } from "../accessControl";
import {
  ANONYMOUS,
  capByBotPolicy,
  evaluate,
  resolveIdentity,
} from "../accessControl";

const { verifyIdToken } = vi.hoisted(() => ({ verifyIdToken: vi.fn() }));

vi.mock("firebase-admin/app", () => ({
  initializeApp: vi.fn(() => ({})),
  cert: vi.fn(() => ({})),
}));

vi.mock("firebase-admin/auth", () => ({
  getAuth: vi.fn(() => ({ verifyIdToken })),
}));

vi.mock("firebase-admin/firestore", () => ({
  getFirestore: vi.fn(() => ({ collection: vi.fn() })),
}));

const human = (email: string | null, uid: string | null = "u"): Identity => ({
  uid,
  email,
  isBot: false,
});

const acl = (board: BoardDoc | null, team: TeamDoc | null = null) => ({
  board,
  team,
});

describe("capByBotPolicy", () => {
  const full = { canRead: true, canWrite: true };

  it("none blocks everything", () => {
    expect(capByBotPolicy(full, "none")).toEqual({
      canRead: false,
      canWrite: false,
    });
  });

  it("read strips write", () => {
    expect(capByBotPolicy(full, "read")).toEqual({
      canRead: true,
      canWrite: false,
    });
  });

  it("write passes through", () => {
    expect(capByBotPolicy(full, "write")).toEqual(full);
  });
});

describe("evaluate — bot vs human", () => {
  it("missing board: human gets full access, bot denied", () => {
    expect(evaluate(human("a@x.io"), acl(null), false)).toEqual({
      canRead: true,
      canWrite: true,
    });
    expect(evaluate(human("a@x.io"), acl(null), true)).toEqual({
      canRead: false,
      canWrite: false,
    });
  });

  it("private board: owner writes; bot owner keeps write under default policy", () => {
    const board: BoardDoc = {
      ownerUid: "u",
      visibility: "private",
      editors: [],
      viewers: [],
    };
    expect(evaluate(human("o@x.io", "u"), acl(board), false)).toEqual({
      canRead: true,
      canWrite: true,
    });
    expect(evaluate(human("o@x.io", "u"), acl(board), true)).toEqual({
      canRead: true,
      canWrite: true,
    });
  });

  it("botPolicy read caps an owner bot to read-only", () => {
    const board: BoardDoc = {
      ownerUid: "u",
      visibility: "private",
      editors: [],
      viewers: [],
      botPolicy: "read",
    };
    expect(evaluate(human("o@x.io", "u"), acl(board), true)).toEqual({
      canRead: true,
      canWrite: false,
    });
  });

  it("botPolicy none denies a bot on a board its user owns", () => {
    const board: BoardDoc = {
      ownerUid: "u",
      visibility: "private",
      editors: [],
      viewers: [],
      botPolicy: "none",
    };
    expect(evaluate(human("o@x.io", "u"), acl(board), true)).toEqual({
      canRead: false,
      canWrite: false,
    });
  });

  it("link board: stranger reads only, as human and as bot", () => {
    const board: BoardDoc = {
      ownerUid: "owner",
      visibility: "link",
      editors: [],
      viewers: [],
    };
    expect(evaluate(human("s@x.io", "s"), acl(board), false)).toEqual({
      canRead: true,
      canWrite: false,
    });
    expect(evaluate(human("s@x.io", "s"), acl(board), true)).toEqual({
      canRead: true,
      canWrite: false,
    });
  });
});

describe("resolveIdentity — bot claim & revocation", () => {
  beforeEach(() => {
    verifyIdToken.mockReset();
  });

  it("no token → anonymous, not a bot", async () => {
    expect(await resolveIdentity(undefined)).toEqual(ANONYMOUS);
    expect(verifyIdToken).not.toHaveBeenCalled();
  });

  it("human token (no claim) → isBot false", async () => {
    verifyIdToken.mockResolvedValue({ uid: "u1", email: "h@x.io" });
    expect(await resolveIdentity("t")).toEqual({
      uid: "u1",
      email: "h@x.io",
      isBot: false,
    });
  });

  it("bot-claim token → isBot true (server-derived, not client-supplied)", async () => {
    verifyIdToken.mockResolvedValue({ uid: "u1", email: "h@x.io", bot: true });
    expect((await resolveIdentity("t")).isBot).toBe(true);
  });

  it("verifies the token with checkRevoked enabled", async () => {
    verifyIdToken.mockResolvedValue({ uid: "u1", email: null });
    await resolveIdentity("t");
    expect(verifyIdToken).toHaveBeenCalledWith("t", true);
  });

  it("verify failure (revoked/invalid) → anonymous", async () => {
    verifyIdToken.mockRejectedValue(new Error("revoked"));
    expect(await resolveIdentity("t")).toEqual(ANONYMOUS);
  });
});
