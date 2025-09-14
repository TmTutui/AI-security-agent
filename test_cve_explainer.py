#!/usr/bin/env python3
"""
Test script for the CVE Explainer Tool.

This script tests the basic functionality of the CVE Explainer Tool
without requiring API keys for the AI models.
"""

import unittest
from unittest.mock import patch, MagicMock
import json
import os
from pathlib import Path

# Import the module to test
from cve_explainer import CVEExplainer, get_available_models


class TestCVEExplainer(unittest.TestCase):
    """Test cases for the CVE Explainer Tool."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a mock environment with API keys
        self.env_patcher = patch.dict('os.environ', {
            'OPENAI_API_KEY': 'test_openai_key',
            'GEMINI_API_KEY': 'test_gemini_key',
            'MISTRAL_API_KEY': 'test_mistral_key',
            'OLLAMA_BASE_URL': 'http://localhost:11434'
        })
        self.env_patcher.start()

    def tearDown(self):
        """Tear down test fixtures."""
        self.env_patcher.stop()

    def test_get_available_models(self):
        """Test that available models are correctly identified based on API keys."""
        available_models = get_available_models()
        
        # Check that all expected providers are available
        self.assertIn('OpenAI', available_models)
        self.assertIn('Gemini', available_models)
        self.assertIn('Mistral', available_models)
        self.assertIn('Ollama', available_models)
        
        # Check that each provider has the expected models
        self.assertIn('openai/gpt-3.5-turbo', available_models['OpenAI'])
        self.assertIn('gemini/gemini-pro', available_models['Gemini'])
        self.assertIn('mistral/mistral-small', available_models['Mistral'])
        self.assertIn('ollama/llama2', available_models['Ollama'])

    @patch('requests.get')
    def test_fetch_cve_data(self, mock_get):
        """Test fetching CVE data from the NVD API."""
        # Mock the API response
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        
        # Load sample CVE data from file
        sample_data_path = Path(__file__).parent / 'test_data' / 'sample_cve_data.json'
        
        # If the test data directory doesn't exist, create it
        if not sample_data_path.parent.exists():
            sample_data_path.parent.mkdir(parents=True)
        
        # If the sample data file doesn't exist, create it with sample data
        if not sample_data_path.exists():
            sample_data = {
                "totalResults": 1,
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-2021-44228",
                        "descriptions": [{
                            "lang": "en",
                            "value": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled."
                        }],
                        "metrics": {
                            "cvssMetricV31": [{
                                "cvssData": {
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL"
                                }
                            }],
                            "cvssMetricV2": [{
                                "cvssData": {
                                    "baseScore": 7.5
                                }
                            }]
                        },
                        "configurations": [{
                            "nodes": [{
                                "cpeMatch": [{
                                    "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                    "vulnerable": True
                                }]
                            }]
                        }]
                    }
                }]
            }
            with open(sample_data_path, 'w') as f:
                json.dump(sample_data, f)
        
        # Load the sample data
        with open(sample_data_path, 'r') as f:
            sample_data = json.load(f)
        
        mock_response.json.return_value = sample_data
        mock_get.return_value = mock_response
        
        # Initialize the CVE Explainer with a mock model
        with patch('cve_explainer.CVEExplainer._initialize_model'):
            explainer = CVEExplainer('openai/gpt-3.5-turbo')
            explainer.llm = MagicMock()
            
            # Test fetching CVE data
            cve_data = explainer.fetch_cve_data('CVE-2021-44228')
            
            # Check that the API was called with the correct URL
            mock_get.assert_called_once_with(
                'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228'
            )
            
            # Check that the returned data is correct
            self.assertEqual(cve_data['totalResults'], 1)
            self.assertEqual(
                cve_data['vulnerabilities'][0]['cve']['id'],
                'CVE-2021-44228'
            )

    def test_load_codebase_nonexistent_path(self):
        """Test loading a codebase from a nonexistent path."""
        with patch('cve_explainer.CVEExplainer._initialize_model'):
            explainer = CVEExplainer('openai/gpt-3.5-turbo')
            explainer.llm = MagicMock()
            
            # Test loading a nonexistent path
            documents = explainer.load_codebase('/nonexistent/path')
            
            # Check that an empty list is returned
            self.assertEqual(documents, [])


if __name__ == '__main__':
    unittest.main()