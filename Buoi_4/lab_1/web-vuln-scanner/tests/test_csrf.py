import unittest
from scanners.csrf_detector import CSRFDetector


class TestCSRF(unittest.TestCase):
    def test_token_present(self):
        self.assertTrue(CSRFDetector().scan('<form><input value="abc" name="_csrf"></form>')['csrf_protected'])

    def test_missing_token(self):
        self.assertEqual(CSRFDetector().scan('<form></form>')['status'], 'potential')

    def test_each_form_checked(self):
        result = CSRFDetector().scan('<form><input name="csrf_token" value="x"></form><form></form>')
        self.assertFalse(result['csrf_protected'])
        self.assertEqual(result['param'], 'form[2]')

    def test_empty_token(self):
        self.assertFalse(CSRFDetector().scan('<form><input name="_csrf" value=""></form>')['csrf_protected'])

    def test_no_form(self):
        self.assertEqual(CSRFDetector().scan('<p>Hello</p>')['status'], 'info')
