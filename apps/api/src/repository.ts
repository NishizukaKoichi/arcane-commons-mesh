export type Challenge = {
  id: string;
  valueHash: string;
  expiresAt: number;
  consumed: boolean;
};

export type SessionPrincipal = {
  sessionId: string;
  memberId: string;
  communityId: string;
  publicKey: string;
  roles: string[];
  expiresAt: number;
};

export type Vote = {
  memberId: string;
  choice: "yes" | "no" | "abstain";
  castAt: number;
  memberSignature: string;
};

export type CommonsArtifact = {
  artifactId: string;
  communityId: string;
  ownerMemberId: string;
  kind: string;
  envelopeCid: string;
  encryptedEnvelopeBase64: string;
  createdAt: number;
  ownerSignature: string;
};

export interface AuthRepository {
  createChallenge(valueHash: string, now: number): Promise<Challenge>;
  getChallenge(id: string): Promise<Challenge | undefined>;
  consumeChallengeAndCreateSession(input: {
    challengeId: string;
    replayNonceHash: string;
    memberId: string;
    publicKey: string;
    tokenHash: string;
    now: number;
  }): Promise<SessionPrincipal | undefined>;
  authenticate(tokenHash: string, now: number): Promise<SessionPrincipal | undefined>;
  revokeSession(sessionId: string, now: number): Promise<void>;
}

export class MemoryRepository implements AuthRepository {
  readonly challenges = new Map<string, Challenge>();
  readonly replayNonces = new Set<string>();
  readonly sessions = new Map<string, SessionPrincipal & { tokenHash: string; revokedAt?: number }>();
  readonly members = new Map<
    string,
    {
      communityId: string;
      publicKey: string;
      roles: string[];
      status: string;
      credentialIssuedAt: number;
      credentialExpiresAt: number;
    }
  >();
  readonly votes = new Map<string, Map<string, Vote>>();
  readonly voteHistory: Array<Vote & { proposalId: string }> = [];
  readonly proposals = new Set<string>();
  readonly commonsArtifacts = new Map<string, CommonsArtifact>();

  addMember(input: {
    memberId: string;
    communityId: string;
    publicKey: string;
    roles: string[];
    status?: string;
    credentialIssuedAt?: number;
    credentialExpiresAt?: number;
  }): void {
    this.members.set(input.memberId, {
      communityId: input.communityId,
      publicKey: input.publicKey,
      roles: input.roles,
      status: input.status ?? "active",
      credentialIssuedAt: input.credentialIssuedAt ?? 0,
      credentialExpiresAt: input.credentialExpiresAt ?? Number.MAX_SAFE_INTEGER
    });
  }

  async createChallenge(valueHash: string, now: number): Promise<Challenge> {
    const challenge = {
      id: crypto.randomUUID(),
      valueHash,
      expiresAt: now + 300,
      consumed: false
    };
    this.challenges.set(challenge.id, challenge);
    return challenge;
  }

  async getChallenge(id: string): Promise<Challenge | undefined> {
    return this.challenges.get(id);
  }

  async consumeChallengeAndCreateSession(input: {
    challengeId: string;
    replayNonceHash: string;
    memberId: string;
    publicKey: string;
    tokenHash: string;
    now: number;
  }): Promise<SessionPrincipal | undefined> {
    const challenge = this.challenges.get(input.challengeId);
    const member = this.members.get(input.memberId);
    if (
      !challenge ||
      challenge.consumed ||
      challenge.expiresAt < input.now ||
      this.replayNonces.has(input.replayNonceHash) ||
      !member ||
      member.status !== "active" ||
      member.credentialIssuedAt > input.now ||
      member.credentialExpiresAt <= input.now ||
      member.publicKey !== input.publicKey
    ) {
      return undefined;
    }
    challenge.consumed = true;
    this.replayNonces.add(input.replayNonceHash);
    const principal: SessionPrincipal = {
      sessionId: crypto.randomUUID(),
      memberId: input.memberId,
      communityId: member.communityId,
      publicKey: member.publicKey,
      roles: member.roles,
      expiresAt: input.now + 900
    };
    this.sessions.set(principal.sessionId, { ...principal, tokenHash: input.tokenHash });
    return principal;
  }

  async authenticate(tokenHash: string, now: number): Promise<SessionPrincipal | undefined> {
    const session = [...this.sessions.values()].find(
      (item) => item.tokenHash === tokenHash && !item.revokedAt && item.expiresAt >= now
    );
    const member = session ? this.members.get(session.memberId) : undefined;
    if (
      !session ||
      !member ||
      member.status !== "active" ||
      member.credentialIssuedAt > now ||
      member.credentialExpiresAt <= now
    ) {
      return undefined;
    }
    return session;
  }

  async revokeSession(sessionId: string, now: number): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) session.revokedAt = now;
  }

  recordVote(proposalId: string, vote: Vote): boolean {
    let votes = this.votes.get(proposalId);
    if (!votes) {
      votes = new Map();
      this.votes.set(proposalId, votes);
    }
    if (votes.has(vote.memberId)) return false;
    votes.set(vote.memberId, vote);
    this.voteHistory.push({ proposalId, ...vote });
    return true;
  }
}

type D1ChallengeRow = {
  challenge_id: string;
  challenge_hash: string;
  expires_at: number;
  consumed_at: number | null;
};

type D1PrincipalRow = {
  session_id: string;
  member_id: string;
  community_id: string;
  public_key: string;
  roles_json: string;
  expires_at: number;
};

export class D1Repository implements AuthRepository {
  constructor(private readonly db: D1Database) {}

  async createChallenge(valueHash: string, now: number): Promise<Challenge> {
    const challenge: Challenge = {
      id: crypto.randomUUID(),
      valueHash,
      expiresAt: now + 300,
      consumed: false
    };
    await this.db
      .prepare(
        "INSERT INTO auth_challenges (challenge_id, challenge_hash, expires_at) VALUES (?, ?, ?)"
      )
      .bind(challenge.id, challenge.valueHash, challenge.expiresAt)
      .run();
    return challenge;
  }

  async getChallenge(id: string): Promise<Challenge | undefined> {
    const row = await this.db
      .prepare(
        "SELECT challenge_id, challenge_hash, expires_at, consumed_at FROM auth_challenges WHERE challenge_id = ?"
      )
      .bind(id)
      .first<D1ChallengeRow>();
    return row
      ? {
          id: row.challenge_id,
          valueHash: row.challenge_hash,
          expiresAt: row.expires_at,
          consumed: row.consumed_at !== null
        }
      : undefined;
  }

  async consumeChallengeAndCreateSession(input: {
    challengeId: string;
    replayNonceHash: string;
    memberId: string;
    publicKey: string;
    tokenHash: string;
    now: number;
  }): Promise<SessionPrincipal | undefined> {
    const member = await this.db
      .prepare(
        `SELECT member_id, community_id, public_key, roles_json
         FROM members
         WHERE member_id = ? AND public_key = ? AND status = 'active'
           AND EXISTS (
             SELECT 1 FROM membership_credentials c
             WHERE c.member_id = members.member_id
               AND c.issued_at <= ? AND c.expires_at > ? AND c.revoked_at IS NULL
           )`
      )
      .bind(input.memberId, input.publicKey, input.now, input.now)
      .first<{
        member_id: string;
        community_id: string;
        public_key: string;
        roles_json: string;
      }>();
    if (!member) return undefined;

    const sessionId = crypto.randomUUID();
    const expiresAt = input.now + 900;
    const claimed = await this.db
      .prepare(
        `UPDATE auth_challenges SET consumed_at = ?
         WHERE challenge_id = ? AND consumed_at IS NULL AND expires_at >= ?`
      )
      .bind(input.now, input.challengeId, input.now)
      .run();
    if ((claimed.meta.changes ?? 0) !== 1) return undefined;
    try {
      await this.db.batch([
        this.db
          .prepare(
            "INSERT INTO replay_nonces (nonce_hash, member_id, expires_at) VALUES (?, ?, ?)"
          )
          .bind(input.replayNonceHash, input.memberId, input.now + 300),
        this.db
          .prepare(
            `INSERT INTO sessions (session_id, member_id, token_hash, expires_at)
             VALUES (?, ?, ?, ?)`
          )
          .bind(sessionId, input.memberId, input.tokenHash, expiresAt)
      ]);
    } catch {
      return undefined;
    }
    return {
      sessionId,
      memberId: member.member_id,
      communityId: member.community_id,
      publicKey: member.public_key,
      roles: JSON.parse(member.roles_json) as string[],
      expiresAt
    };
  }

  async authenticate(tokenHash: string, now: number): Promise<SessionPrincipal | undefined> {
    const row = await this.db
      .prepare(
        `SELECT s.session_id, s.member_id, m.community_id, m.public_key, m.roles_json, s.expires_at
         FROM sessions s JOIN members m ON m.member_id = s.member_id
         WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at >= ?
           AND m.status = 'active'
           AND EXISTS (
             SELECT 1 FROM membership_credentials c
             WHERE c.member_id = m.member_id
               AND c.issued_at <= ? AND c.expires_at > ? AND c.revoked_at IS NULL
           )`
      )
      .bind(tokenHash, now, now, now)
      .first<D1PrincipalRow>();
    return row
      ? {
          sessionId: row.session_id,
          memberId: row.member_id,
          communityId: row.community_id,
          publicKey: row.public_key,
          roles: JSON.parse(row.roles_json) as string[],
          expiresAt: row.expires_at
        }
      : undefined;
  }

  async revokeSession(sessionId: string, now: number): Promise<void> {
    await this.db
      .prepare("UPDATE sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL")
      .bind(now, sessionId)
      .run();
  }
}

export function toBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

export function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

export function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export async function hashOpaque(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}
