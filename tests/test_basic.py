"""
Basic tests for ParamBuster functionality.
Run with: python -m pytest tests/test_basic.py
"""

import pytest
from unittest.mock import Mock, patch
import requests
from ParamBuster import ParamBuster


class TestParamBuster:
    """Test basic ParamBuster functionality."""

    def test_initialization_valid(self):
        """Test valid initialization."""
        scanner = ParamBuster("https://example.com")
        assert scanner.url == "https://example.com"
        assert scanner.method == "GET"
        assert scanner.threads == 50

    def test_initialization_invalid_url(self):
        """Test invalid URL handling."""
        with pytest.raises(ValueError, match="Invalid URL provided"):
            ParamBuster("not-a-url")

    def test_initialization_invalid_method(self):
        """Test invalid method handling."""
        with pytest.raises(ValueError, match="Method must be one of"):
            ParamBuster("https://example.com", method="INVALID")

    def test_initialization_invalid_threads(self):
        """Test invalid threads handling."""
        with pytest.raises(ValueError, match="Threads must be between"):
            ParamBuster("https://example.com", threads=0)

    @patch('requests.Session.get')
    def test_detect_parameters_basic(self, mock_get):
        """Test basic parameter detection."""
        # Mock response
        mock_response = Mock()
        mock_response.text = '<html><body><form><input name="test_param"></form></body></html>'
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        scanner = ParamBuster("https://example.com", threads=1)
        scanner.detect_parameters()

        # Should find the form parameter
        assert "test_param" in scanner.parameters
        assert scanner.parameters["test_param"]["source"] == "form_fields"

    def test_url_validation(self):
        """Test URL validation."""
        scanner = ParamBuster.__new__(ParamBuster)  # Create without __init__

        # Valid URLs
        assert scanner.validate_url("https://example.com") == "https://example.com"
        assert scanner.validate_url("http://test.com/path") == "http://test.com/path"

        # Invalid URLs
        assert scanner.validate_url("not-a-url") is None
        assert scanner.validate_url("") is None

    def test_analyze_sinks(self):
        """Test sink analysis."""
        scanner = ParamBuster("https://example.com")

        # Test dangerous sinks
        dangerous_html = '<script>innerHTML = "test";</script><div onclick="alert(1)"></div>'
        sinks = scanner.analyze_sinks(dangerous_html)

        assert len(sinks["dangerous"]) > 0
        assert "innerHTML" in str(sinks["dangerous"])

    def test_detect_reflection(self):
        """Test reflection detection."""
        scanner = ParamBuster("https://example.com")

        test_html = '<div id="test123">Content</div><input value="test123">'
        unique_val = "test123"

        assert scanner.detect_reflection(test_html, unique_val)

        # Test non-reflection
        non_reflective_html = '<div id="other">Content</div>'
        assert not scanner.detect_reflection(non_reflective_html, unique_val)


class TestParamBusterIntegration:
    """Integration tests for ParamBuster."""

    @patch('requests.Session.get')
    def test_full_scan_workflow(self, mock_get):
        """Test complete scanning workflow."""
        # Mock base response
        mock_response = Mock()
        mock_response.text = '''
        <html>
        <body>
            <form><input name="username"><input name="password"></form>
            <script>var api_key = "test";</script>
        </body>
        </html>
        '''
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        scanner = ParamBuster("https://example.com", threads=1, max_requests=10)

        # Mock parameter testing responses
        with patch.object(scanner.session, 'get', return_value=Mock(text="reflected_test", status_code=200)):
            results = scanner.run()

        assert "parameters" in results
        assert "vulnerabilities" in results
        assert isinstance(results["parameters"], dict)
        assert isinstance(results["vulnerabilities"], dict)


if __name__ == "__main__":
    pytest.main([__file__])