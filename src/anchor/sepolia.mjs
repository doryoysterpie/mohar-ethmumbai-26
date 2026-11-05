import { createPublicClient, createWalletClient, http, parseTransaction, keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';

const ROOT = /^[0-9a-f]{64}$/;

/** @param {string} url */
const publicClient = (url) => createPublicClient({ chain: sepolia, transport: http(url, { timeout: 15_000, retryCount: 0 }) });

/**
 * Tries `fn` against each RPC URL in order and returns the first success.
 * @template T
 * @param {string[]} rpcUrls
 * @param {(url: string) => Promise<T>} fn
 * @returns {Promise<{ value: T, rpc: string }>}
 */
async function firstOk(rpcUrls, fn) {
  if (!Array.isArray(rpcUrls) || rpcUrls.length === 0) throw new Error('no RPC URL configured');
  const errors = [];
  for (const url of rpcUrls) {
    try {
      return { value: await fn(url), rpc: url };
    } catch (e) {
      errors.push(`${new URL(url).host}: ${e.shortMessage ?? e.message}`);
    }
  }
  throw new Error(`every RPC failed: ${errors.join('; ')}`);
}

/**
 * Writes a batch root as the calldata of a zero-value transaction from the operator to itself on Ethereum Sepolia.
 * The transaction is signed once and the same signed bytes are sent to each RPC in turn, so a fallback never
 * sends a second transaction.
 * @param {{ rootHex: string, privateKey: `0x${string}`, rpcUrls: string[], confirmations?: number, timeoutMs?: number, pollMs?: number }} p
 * @returns {Promise<{ tx_hash: string, block_number: number, from: string, rpc: string }>}
 */
export async function anchorRoot({ rootHex, privateKey, rpcUrls, confirmations = 1, timeoutMs = 180_000, pollMs = 4_000 }) {
  if (!ROOT.test(rootHex)) throw new Error('root must be 64 lowercase hex characters');
  const account = privateKeyToAccount(privateKey);
  const { value: request } = await firstOk(rpcUrls, (url) => createWalletClient({ account, chain: sepolia, transport: http(url, { timeout: 15_000, retryCount: 0 }) })
    .prepareTransactionRequest({ to: account.address, value: 0n, data: `0x${rootHex}` }));
  const signed = await account.signTransaction(request);
  const { value: hash } = await firstOk(rpcUrls, async (url) => {
    try {
      return await publicClient(url).sendRawTransaction({ serializedTransaction: signed });
    } catch (e) {
      // Another RPC may already have accepted these exact bytes.
      if (/already known|known transaction|nonce too low/i.test(e.details ?? e.message ?? '')) {
        return keccak256(signed);
      }
      throw e;
    }
  });
  const { receipt, rpc } = await waitForReceipt({ hash, rpcUrls, confirmations, timeoutMs, pollMs });
  if (receipt.status !== 'success') throw new Error(`anchor transaction ${hash} failed`);
  return { tx_hash: hash, block_number: Number(receipt.blockNumber), from: account.address, rpc };
}

/**
 * Polls every RPC in turn until one returns a receipt with the required confirmations, or the timeout passes.
 * An RPC that errors is skipped for that round.
 */
async function waitForReceipt({ hash, rpcUrls, confirmations, timeoutMs, pollMs }) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    for (const url of rpcUrls) {
      try {
        const c = publicClient(url);
        const receipt = await c.getTransactionReceipt({ hash });
        const head = await c.getBlockNumber();
        if (head - receipt.blockNumber + 1n >= BigInt(confirmations)) return { receipt, rpc: url };
      } catch {
        // not mined yet on this RPC, or this RPC is down
      }
    }
    if (Date.now() >= deadline) throw new Error(`no receipt for ${hash} within ${timeoutMs} ms`);
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/**
 * Reads a transaction from Sepolia and returns its calldata (without 0x) and block number.
 * @param {{ txHash: string, rpcUrls: string[] }} p
 * @returns {Promise<{ calldata: string, block_number: number | null, from: string, to: string | null }>}
 */
export async function readAnchor({ txHash, rpcUrls }) {
  const { value: tx } = await firstOk(rpcUrls, (url) => publicClient(url).getTransaction({ hash: /** @type {`0x${string}`} */ (txHash) }));
  return {
    calldata: tx.input.replace(/^0x/, '').toLowerCase(),
    block_number: tx.blockNumber === null ? null : Number(tx.blockNumber),
    from: tx.from.toLowerCase(),
    to: tx.to ? tx.to.toLowerCase() : null,
  };
}

/**
 * Chain id the RPCs report (first that answers). The client is configured for Sepolia, but does not itself check that
 * the RPC is on Sepolia, so a verifier asks.
 * @param {string[]} rpcUrls
 * @returns {Promise<number>}
 */
export async function chainIdOf(rpcUrls) {
  const { value } = await firstOk(rpcUrls, (url) => publicClient(url).getChainId());
  return value;
}

/** Calldata of a signed raw transaction, without 0x. */
export function calldataOf(serialized) {
  return (parseTransaction(serialized).data ?? '0x').replace(/^0x/, '').toLowerCase();
}
