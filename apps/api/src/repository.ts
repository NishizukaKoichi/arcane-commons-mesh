export type Challenge = {
  id: string;
  value: string;
  expiresAt: number;
  consumed: boolean;
};

export type Vote = {
  memberId: string;
  choice: "yes" | "no" | "abstain";
  castAt: number;
  memberSignature: string;
};

export class MemoryRepository {
  readonly challenges = new Map<string, Challenge>();
  readonly replayNonces = new Set<string>();
  readonly votes = new Map<string, Map<string, Vote>>();
  readonly voteHistory: Array<Vote & { proposalId: string }> = [];
  readonly proposals = new Set<string>();

  createChallenge(now: number): Challenge {
    const random = crypto.getRandomValues(new Uint8Array(32));
    const value = toBase64Url(random);
    const challenge = {
      id: crypto.randomUUID(),
      value,
      expiresAt: now + 300,
      consumed: false
    };
    this.challenges.set(challenge.id, challenge);
    return challenge;
  }

  consumeChallenge(id: string, replayNonce: string, now: number): Challenge | undefined {
    const challenge = this.challenges.get(id);
    if (
      !challenge ||
      challenge.consumed ||
      challenge.expiresAt < now ||
      this.replayNonces.has(replayNonce)
    ) {
      return undefined;
    }
    challenge.consumed = true;
    this.replayNonces.add(replayNonce);
    return challenge;
  }

  recordVote(proposalId: string, vote: Vote): void {
    let votes = this.votes.get(proposalId);
    if (!votes) {
      votes = new Map();
      this.votes.set(proposalId, votes);
    }
    votes.set(vote.memberId, vote);
    this.voteHistory.push({ proposalId, ...vote });
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
