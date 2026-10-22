"""Small compatibility tests for the Python pool implementation."""
import unittest

import pool


class PoolCompatibilityTests(unittest.TestCase):
    def test_model_id_matches_typescript_reference(self):
        self.assertEqual(pool.MODEL_ID, 'b841270f45ea6de9')

    def test_model_output_matches_typescript_reference(self):
        result = pool.run_job('hello', 8, '00' * 31 + '01', (1 << 256) // 1000, (1 << 256) // 1000 // 32)
        self.assertEqual(result, {'output': 'W#WTg#g#', 'win': -1, 'steps': 13, 'shares': []})

    def test_wallet_signatures_and_transaction_ids(self):
        wallet = pool.Wallet('test-wallet')
        body = {'type': 'job', 'from': wallet.address, 'prompt': 'hello', 'maxTokens': 8, 'fee': 2, 'nonce': 0}
        tx = wallet.make_tx(body)
        self.assertEqual(tx['id'], pool.sha256(pool.canon(body)))
        self.assertTrue(pool.verify_sig(wallet.address, tx['id'], tx['sig']))
        self.assertFalse(pool.verify_sig(wallet.address, 'tampered', tx['sig']))

    def test_canonical_json_sorts_nested_keys(self):
        self.assertEqual(pool.canon({'z': 1, 'a': {'y': 2, 'b': 3}}), '{"a":{"b":3,"y":2},"z":1}')


if __name__ == '__main__':
    unittest.main()
