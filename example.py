#!/usr/bin/env python3
"""
Example usage of the CVE Explainer Tool.

This script demonstrates how to use the CVE Explainer Tool programmatically.
"""

import os
from dotenv import load_dotenv
from cve_explainer import CVEExplainer

# Load environment variables
load_dotenv()

def main():
    """Demonstrate the usage of the CVE Explainer Tool."""
    # Example CVE ID (Log4Shell vulnerability)
    cve_id = "CVE-2021-44228"
    
    # Example codebase path (current directory)
    codebase_path = os.getcwd()
    
    # Choose a model (make sure you have the API key in .env)
    model_name = "openai/gpt-3.5-turbo"  # Change this to a model you have API key for
    
    print(f"Analyzing {cve_id} using {model_name}...\n")
    
    # Initialize the CVE Explainer
    explainer = CVEExplainer(model_name)
    
    # Option 1: Get only CVE information without codebase analysis
    print("\n=== CVE Information Only (With Enhanced Vulnerability Data) ===\n")
    cve_info = explainer.analyze_cve(cve_id)
    print(cve_info)
    
    # You can also access the raw vulnerability data
    print("\n=== Raw Vulnerability Data ===\n")
    nvd_data = explainer.fetch_cve_data(cve_id)
    additional_data = explainer.fetch_additional_vulnerability_data(cve_id)
    
    print(f"NVD Data Available: {bool(nvd_data)}")
    print(f"MITRE Data Available: {bool(additional_data.get('mitre'))}")
    print(f"EPSS Data Available: {bool(additional_data.get('epss'))}")
    print(f"GitHub Data Available: {bool(additional_data.get('github'))}")
    
    # If EPSS data is available, show the exploit probability
    if additional_data.get("epss"):
        epss_data = additional_data["epss"]
        print(f"\nEPSS Score: {epss_data.get('epss', 'N/A')}")
        print(f"EPSS Percentile: {epss_data.get('percentile', 'N/A')}")
        print("(Higher scores indicate higher probability of exploitation)")
    
    # If GitHub data is available, show related repositories
    if additional_data.get("github") and additional_data["github"].get("related_repositories"):
        github_repos = additional_data["github"]["related_repositories"]
        print("\nRelated GitHub Repositories:")
        for repo in github_repos:
            print(f"- {repo['name']}: {repo['url']}")

    
    # Option 2: Get CVE information and analyze its relevance to a codebase
    print("\n=== CVE Information with Codebase Analysis ===\n")
    full_analysis = explainer.analyze_cve(cve_id, codebase_path)
    print(full_analysis)
    
    # Save the analysis to a file
    output_file = f"{cve_id.replace('-', '_')}_example_analysis.md"
    with open(output_file, "w") as f:
        f.write(full_analysis)
    
    print(f"\nAnalysis saved to {output_file}")


if __name__ == "__main__":
    main()