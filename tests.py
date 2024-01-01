"""Unit tests for gofilecli module"""
import unittest
import gofilecli


class TestUrlValidation(unittest.TestCase):
    """Test gofile URL parsing"""

    def test_valid(self):
        """Test valid gofile URLs"""
        self.assertEqual(gofilecli.validate_url("https://gofile.io/d/P9HJd8"), "P9HJd8")
        self.assertEqual(gofilecli.validate_url("https://gofile.io/d/RJU3wf"), "RJU3wf")

    def test_invalid(self):
        """Test invalid gofile URLs"""
        self.assertIsNone(gofilecli.validate_url("https://docs.python.org/3/library/sys.html"))
        self.assertIsNone(gofilecli.validate_url("https://www.youtube.com"))
        self.assertIsNone(gofilecli.validate_url("https://gofile.io/api"))
        self.assertIsNone(gofilecli.validate_url("xetcrytfbugyn"))


if __name__ == "__main__":
    unittest.main()
