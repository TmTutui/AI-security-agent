"""
Data Fetcher Module

This module handles fetching CVE data from various sources.
"""

import requests
from typing import Dict


class DataFetcher:
    """Handles fetching CVE data from various sources."""
    
    def __init__(self, llm=None):
        """Initialize the Data Fetcher.
        
        Args:
            llm: Optional language model to use for data processing.
        """
        self.llm = llm

    def fetch_cve_data(self, cve_id: str) -> Dict:
        """Fetch CVE data from the NVD API.

        Args:
            cve_id: The CVE identifier (e.g., CVE-2021-44228).

        Returns:
            A dictionary containing the CVE data.

        Raises:
            Exception: If the CVE data cannot be fetched.
        """
        try:
            # Use the NVD API to fetch CVE data
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            
            if data.get("totalResults", 0) == 0:
                raise Exception(f"No data found for {cve_id}")
            
            # Extract the first vulnerability and clean it up
            vulnerability = data["vulnerabilities"][0]["cve"]
            
            # Keep only the English description
            english_description = next((desc["value"] for desc in vulnerability["descriptions"] if desc["lang"] == "en"), None)
            vulnerability["descriptions"] = english_description
            
            cleaned_data = {
                "cve": vulnerability
            }
            return cleaned_data
        except Exception as e:
            print(f"Error fetching CVE data: {e}")
            raise
            
    def fetch_additional_vulnerability_data(self, cve_id: str) -> Dict:
        """Fetch additional vulnerability data from multiple sources.
        
        Args:
            cve_id: The CVE identifier (e.g., CVE-2021-44228).
            
        Returns:
            A dictionary containing additional vulnerability data.
        """
        additional_data = {}

        # Try to fetch data from OSV CVE
        try:
            osv_url = f"https://api.osv.dev/v1/vulns/{cve_id}"
            response = requests.get(osv_url)
            if response.status_code == 200:
                osv_data = response.json()
                if osv_data:
                    additional_data["osv"] = osv_data
        except Exception as e:
            print(f"Error fetching OSV data: {e}")
        
        # Try to fetch data from MITRE CVE
        try:
            # MITRE CVE API
            mitre_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            mitre_response = requests.get(mitre_url)
            if mitre_response.status_code == 200:
                additional_data["mitre"] = mitre_response.json()
        except Exception as e:
            print(f"Error fetching MITRE data: {e}")
        
        # Try to fetch EPSS (Exploit Prediction Scoring System) data
        try:
            # EPSS API
            epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            epss_response = requests.get(epss_url)
            if epss_response.status_code == 200:
                epss_data = epss_response.json()
                if epss_data.get("data") and len(epss_data["data"]) > 0:
                    additional_data["epss"] = epss_data["data"][0]
        except Exception as e:
            print(f"Error fetching EPSS data: {e}")
        
        # Try to fetch data from GitHub Advisory Database
        try:
            # GitHub Security Advisory API
            github_url = f"https://api.github.com/search/repositories?q={cve_id}+in:readme"
            github_response = requests.get(github_url)
            if github_response.status_code == 200:
                github_data = github_response.json()
                if github_data.get("items"):
                    additional_data["github"] = {
                        "related_repositories": [
                            {"name": repo["full_name"], "url": repo["html_url"]}
                            for repo in github_data["items"][:5]  # Limit to 5 repositories
                        ]
                    }
        except Exception as e:
            print(f"Error fetching GitHub data: {e}")
            
        return additional_data