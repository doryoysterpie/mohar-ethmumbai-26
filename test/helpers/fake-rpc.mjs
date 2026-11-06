// A minimal Ethereum JSON-RPC server for tests: accepts raw transactions, mines each one into its own block.
import http from 'node:http';
import { keccak256, parseTransaction, recoverTransactionAddress, toHex } from 'viem';

/**
 * @param {{ fail?: boolean }} [options] fail: every call returns a JSON-RPC error
 */
export async function fakeRpc(options = {}) {
  const state = { fail: Boolean(options.fail), txs: new Map(), block: 100, nonces: new Map(), calls: [] };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', async () => {
      const msgs = JSON.parse(body);
      const one = async (m) => {
        state.calls.push(m.method);
        if (state.fail) return { jsonrpc: '2.0', id: m.id, error: { code: -32000, message: 'unavailable' } };
        const r = (result) => ({ jsonrpc: '2.0', id: m.id, result });
        const [a] = m.params ?? [];
        switch (m.method) {
          case 'eth_chainId': return r('0xaa36a7');
          case 'eth_blockNumber': return r(toHex(state.block));
          case 'eth_getTransactionCount': return r(toHex(state.nonces.get(String(a).toLowerCase()) ?? 0));
          case 'eth_estimateGas': return r('0x5a3c');
          case 'eth_gasPrice': return r('0x3b9aca00');
          case 'eth_maxPriorityFeePerGas': return r('0x3b9aca00');
          case 'eth_getBlockByNumber': return r({ number: toHex(state.block), baseFeePerGas: '0x3b9aca00', hash: `0x${'11'.repeat(32)}`, timestamp: '0x1', transactions: [] });
          case 'eth_sendRawTransaction': {
            const hash = keccak256(a);
            if (state.txs.has(hash)) return { jsonrpc: '2.0', id: m.id, error: { code: -32000, message: 'already known' } };
            const tx = parseTransaction(a);
            const from = (await recoverTransactionAddress({ serializedTransaction: a })).toLowerCase();
            state.block += 1;
            state.nonces.set(from, (state.nonces.get(from) ?? 0) + 1);
            state.txs.set(hash, { raw: a, tx, from, block: state.block });
            return r(hash);
          }
          case 'eth_getTransactionReceipt': {
            const t = state.txs.get(a);
            if (!t) return r(null);
            return r({ transactionHash: a, blockNumber: toHex(t.block), blockHash: `0x${'22'.repeat(32)}`, status: '0x1', from: t.from, to: t.tx.to, transactionIndex: '0x0', gasUsed: '0x5a3c', cumulativeGasUsed: '0x5a3c', effectiveGasPrice: '0x3b9aca00', logs: [], logsBloom: `0x${'00'.repeat(256)}`, type: '0x2', contractAddress: null });
          }
          case 'eth_getTransactionByHash': {
            const t = state.txs.get(a);
            if (!t) return r(null);
            return r({ hash: a, from: t.from, to: t.tx.to, input: t.tx.data ?? '0x', blockNumber: toHex(t.block), blockHash: `0x${'22'.repeat(32)}`, transactionIndex: '0x0', nonce: toHex(t.tx.nonce ?? 0), value: '0x0', gas: '0x5a3c', type: '0x2', chainId: '0xaa36a7', maxFeePerGas: '0x77359400', maxPriorityFeePerGas: '0x3b9aca00', v: '0x0', r: `0x${'33'.repeat(32)}`, s: `0x${'44'.repeat(32)}`, yParity: '0x0', accessList: [] });
          }
          default: return { jsonrpc: '2.0', id: m.id, error: { code: -32601, message: `no ${m.method}` } };
        }
      };
      const out = Array.isArray(msgs) ? await Promise.all(msgs.map(one)) : await one(msgs);
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(out));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, state, close: () => server.close() };
}
