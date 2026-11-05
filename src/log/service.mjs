import { assertCommitment, firstBreak } from './chain.mjs';
import { merkleRoot, merklePath } from './merkle.mjs';
import { otsStamp, otsUpgrade, otsState } from '../anchor/ots.mjs';
import { anchorRoot } from '../anchor/sepolia.mjs';

/**
 * The log service. It accepts only `{ entry_type, commitment }`, where the commitment is a SHA-256 hex string.
 * @param {{
 *   store: ReturnType<typeof import('./store.mjs').openLogStore>,
 *   clock?: () => Date,
 *   sepolia?: { privateKey: `0x${string}`, rpcUrls: string[] } | null,
 *   ots?: boolean,
 *   stamp?: typeof otsStamp, upgrade?: typeof otsUpgrade, anchor?: typeof anchorRoot,
 * }} config
 */
export function createLog(config) {
  const { store } = config;
  const clock = config.clock ?? (() => new Date());
  const stamp = config.stamp ?? otsStamp;
  const upgrade = config.upgrade ?? otsUpgrade;
  const anchor = config.anchor ?? anchorRoot;

  async function anchorSepolia(batchId, root) {
    if (!config.sepolia) return store.setSepolia(batchId, { error: 'Sepolia anchoring is not configured' });
    try {
      const a = await anchor({ rootHex: root, ...config.sepolia });
      store.setSepolia(batchId, { tx: a.tx_hash, block: a.block_number });
    } catch (e) {
      store.setSepolia(batchId, { error: e.message });
    }
  }

  async function anchorOts(batchId, root) {
    if (config.ots === false) return store.setOts(batchId, { error: 'OpenTimestamps is not configured' });
    try {
      const proof = await stamp(root);
      const s = otsState(proof, root);
      store.setOts(batchId, { proof, state: s.state, height: s.bitcoin_height });
    } catch (e) {
      store.setOts(batchId, { error: e.message });
    }
  }

  return {
    /** Appends a commitment. Returns the entry (existing one if the same type and commitment were committed before). */
    commit({ entry_type: entryType, commitment }) {
      assertCommitment(entryType, commitment);
      return store.append(entryType, commitment, clock().toISOString());
    },

    /**
     * Closes a batch over every unbatched entry, then anchors its root to Sepolia and OpenTimestamps.
     * Anchor failures are recorded on the batch; the batch itself stays closed.
     * @returns {Promise<object | null>} the batch, or null when there is nothing to batch
     */
    async closeBatch() {
      const entries = store.unbatched();
      if (entries.length === 0) return null;
      const prev = entries[0].seq === 0 ? null : store.db.prepare('SELECT seq, entry_hash FROM entries WHERE seq = ?').get(entries[0].seq - 1);
      if (firstBreak(entries, prev) !== -1) throw new Error('the log chain is broken; batch not closed');
      const root = merkleRoot(entries.map((e) => e.entry_hash));
      const batchId = store.closeBatch(entries, root, clock().toISOString());
      await Promise.all([anchorSepolia(batchId, root), anchorOts(batchId, root)]);
      return this.batch(batchId);
    },

    /**
     * Anchors every closed batch that has no Sepolia transaction or no OpenTimestamps proof yet
     * (an earlier attempt failed, or the anchor was not configured when the batch closed).
     */
    async anchorPending() {
      const out = [];
      for (const b of store.batches()) {
        const tasks = [];
        if (!b.sepolia_tx && config.sepolia) tasks.push(anchorSepolia(b.batch_id, b.root));
        if (!b.ots_proof && config.ots !== false) tasks.push(anchorOts(b.batch_id, b.root));
        if (tasks.length === 0) continue;
        await Promise.all(tasks);
        out.push(this.batch(b.batch_id));
      }
      return out;
    },

    /** Asks the calendars to upgrade every pending OpenTimestamps proof. */
    async upgradePending() {
      const out = [];
      for (const b of store.batches().filter((x) => x.ots_state === 'pending' && x.ots_proof)) {
        try {
          const { proof, changed } = await upgrade(new Uint8Array(b.ots_proof));
          const s = otsState(proof, b.root);
          if (changed) store.setOts(b.batch_id, { proof, state: s.state, height: s.bitcoin_height });
          out.push({ batch_id: b.batch_id, state: s.state, bitcoin_height: s.bitcoin_height ?? null });
        } catch (e) {
          out.push({ batch_id: b.batch_id, state: 'pending', error: e.message });
        }
      }
      return out;
    },

    /** Batch summary with both anchors reported separately. */
    batch(batchId) {
      const b = store.batch(batchId);
      if (!b) return null;
      return {
        batch_id: b.batch_id,
        first_seq: b.first_seq,
        last_seq: b.last_seq,
        size: b.size,
        root: b.root,
        closed_at: b.closed_at,
        sepolia: b.sepolia_tx
          ? { state: 'confirmed', chain_id: 11155111, tx_hash: b.sepolia_tx, block_number: b.sepolia_block }
          : { state: 'not_anchored', error: b.sepolia_error },
        ots: b.ots_proof
          ? { state: b.ots_state, bitcoin_height: b.ots_height, proof: Buffer.from(b.ots_proof).toString('base64') }
          : { state: 'not_anchored', error: b.ots_error },
      };
    },

    /**
     * Proof for a commitment: its log entry, its Merkle path and the batch with both anchors.
     * The entry is returned without a batch while its batch is still open.
     */
    proof(commitment) {
      if (typeof commitment !== 'string' || !/^[0-9a-f]{64}$/.test(commitment)) return null;
      const entry = store.entryByCommitment(commitment);
      if (!entry) return null;
      const { batch_id: batchId, ...fields } = entry;
      if (batchId === null) return { entry: fields, batch: null, merkle_path: null };
      const hashes = store.batchEntries(batchId).map((e) => e.entry_hash);
      const index = hashes.indexOf(entry.entry_hash);
      return { entry: fields, merkle_path: merklePath(hashes, index), batch: this.batch(batchId) };
    },
  };
}
