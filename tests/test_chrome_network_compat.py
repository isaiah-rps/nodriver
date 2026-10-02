import asyncio
import unittest

from nodriver import cdp
from nodriver.core.connection import Transaction


def cookie_payload():
    return {
        'name': 'session', 'value': 'test-cookie-value', 'domain': '.example.com',
        'path': '/', 'expires': -1, 'size': 24, 'httpOnly': True,
        'secure': True, 'session': True, 'sameSite': 'None',
        'priority': 'Medium', 'sourceScheme': 'Secure', 'sourcePort': 443,
    }


class ChromeNetworkCompatibilityTests(unittest.TestCase):
    def test_current_chrome_cookie_without_same_party(self):
        cookie = cdp.network.Cookie.from_json(cookie_payload())
        self.assertEqual(cookie.name, 'session')
        self.assertFalse(cookie.same_party)
        self.assertTrue(cookie.http_only)

    def test_legacy_cookie_retains_same_party(self):
        payload = cookie_payload()
        payload['sameParty'] = True
        self.assertTrue(cdp.network.Cookie.from_json(payload).same_party)

    def test_current_chrome_security_policy(self):
        payload = {
            'initiatorIsSecureContext': True,
            'initiatorIPAddressSpace': 'Public',
            'localNetworkAccessRequestPolicy': 'Allow',
        }
        state = cdp.network.ClientSecurityState.from_json(payload)
        self.assertEqual(state.private_network_request_policy.value, 'Allow')

    def test_legacy_security_policy(self):
        state = cdp.network.ClientSecurityState.from_json({
            'initiatorIsSecureContext': False,
            'initiatorIPAddressSpace': 'Local',
            'privateNetworkRequestPolicy': 'PreflightBlock',
        })
        self.assertEqual(state.private_network_request_policy.value, 'PreflightBlock')

    def test_network_event_with_current_chrome_cookie_and_policy(self):
        event = cdp.util.parse_json_event({
            'method': 'Network.requestWillBeSentExtraInfo',
            'params': {
                'requestId': 'request-1',
                'associatedCookies': [{'cookie': cookie_payload(), 'blockedReasons': []}],
                'headers': {'Accept': '*/*'},
                'connectTiming': {'requestTime': 123.45},
                'clientSecurityState': {
                    'initiatorIsSecureContext': True,
                    'initiatorIPAddressSpace': 'Public',
                    'localNetworkAccessRequestPolicy': 'PermissionBlock',
                },
            },
        })
        self.assertEqual(event.associated_cookies[0].cookie.name, 'session')
        self.assertEqual(event.client_security_state.private_network_request_policy.value, 'PermissionBlock')


class TransactionParsingTests(unittest.IsolatedAsyncioTestCase):
    async def test_cookie_response_completes_transaction(self):
        transaction = Transaction(cdp.network.get_cookies())
        transaction(id=1, result={'cookies': [cookie_payload()]})
        cookies = await asyncio.wait_for(transaction, 1)
        self.assertEqual(cookies[0].domain, '.example.com')

    async def test_missing_field_fails_transaction_without_response_values(self):
        transaction = Transaction(cdp.network.get_cookies())
        transaction(id=1, result={'cookies': [{'value': 'test-cookie-value'}]})
        self.assertTrue(transaction.done())
        with self.assertRaises(KeyError) as caught:
            await asyncio.wait_for(transaction, 1)
        self.assertNotIn('test-cookie-value', str(caught.exception))
        self.assertIn('name', str(caught.exception))

    async def test_other_parse_error_completes_transaction(self):
        def invalid_parser():
            yield {'method': 'Test.parse'}
            raise ValueError('Unsupported protocol value')
        transaction = Transaction(invalid_parser())
        transaction(id=1, result={})
        self.assertTrue(transaction.done())
        with self.assertRaises(ValueError):
            await asyncio.wait_for(transaction, 1)

    async def test_successful_transaction_still_completes(self):
        transaction = Transaction(cdp.network.get_cookies())
        transaction(id=1, result={'cookies': []})
        self.assertEqual(await transaction, [])
        transaction(id=1, result={'cookies': []})
        self.assertEqual(await transaction, [])


if __name__ == '__main__':
    unittest.main()
