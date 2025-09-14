#!/usr/bin/env python3
"""
CVE Explainer Tool

A tool to help security engineers understand vulnerability reports (CVE).
This script uses LangChain to interact with various AI models to provide
detailed information about CVEs and their relevance to a codebase.
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Union
import requests
import json

# LangChain imports
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.document_loaders import TextLoader, DirectoryLoader

# Load environment variables
from dotenv import load_dotenv

# Model imports - conditionally imported based on available API keys


class CVEExplainer:
    """CVE Explainer Tool to analyze vulnerabilities and their relevance to a codebase."""

    def __init__(self, model_name: str):
        """Initialize the CVE Explainer with the specified model.

        Args:
            model_name: The name of the AI model to use.
        """
        self.model_name = model_name
        self.llm = self._initialize_model()
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=4000,
            chunk_overlap=200,
            length_function=len,
        )

    def _initialize_model(self):
        """Initialize the specified AI model.

        Returns:
            An initialized LLM instance.

        Raises:
            ValueError: If the model is not supported or the API key is missing.
        """
        if self.model_name.startswith("openai"):
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model_name=self.model_name, temperature=0)
        
        elif self.model_name.startswith("gemini"):
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(model=self.model_name, temperature=0)
        
        elif self.model_name.startswith("mistral"):
            from langchain_mistralai.chat_models import ChatMistralAI
            return ChatMistralAI(model=self.model_name, temperature=0)
        
        elif self.model_name.startswith("ollama"):
            from langchain_community.llms import Ollama
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            return Ollama(model=self.model_name.replace("ollama/", ""), base_url=base_url)
        
        else:
            raise ValueError(f"Unsupported model: {self.model_name}")

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
                
            return data
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

    def load_codebase(self, path: str) -> List[Document]:
        """Load the codebase from the specified path.

        Args:
            path: The path to the codebase.

        Returns:
            A list of Document objects containing the codebase content.
        """
        try:
            path_obj = Path(path)
            if not path_obj.exists():
                raise ValueError(f"Path does not exist: {path}")

            if path_obj.is_file():
                loader = TextLoader(path)
                documents = loader.load()
            else:
                # Load all text files from the directory
                loader = DirectoryLoader(
                    path,
                    glob="**/*.*",
                    exclude=["**/.git/**", "**/node_modules/**", "**/__pycache__/**"],
                    loader_cls=TextLoader,
                    show_progress=True,
                    silent_errors=True,
                )
                documents = loader.load()

            # Split documents into chunks
            split_docs = self.text_splitter.split_documents(documents)
            return split_docs
        except Exception as e:
            print(f"Error loading codebase: {e}")
            return []

    def analyze_cve(self, cve_id: str, codebase_path: Optional[str] = None) -> str:
        """Analyze the CVE and its relevance to the codebase.

        Args:
            cve_id: The CVE identifier (e.g., CVE-2021-44228).
            codebase_path: The path to the codebase to analyze.

        Returns:
            A string containing the analysis results.
        """
        try:
            # Fetch CVE data from NVD
            cve_data = self.fetch_cve_data(cve_id)
            
            # Fetch additional vulnerability data from other sources
            additional_data = self.fetch_additional_vulnerability_data(cve_id)
            
            # Extract relevant information from the CVE data
            cve_item = cve_data.get("vulnerabilities", [])[0].get("cve", {})
            description = cve_item.get("descriptions", [])[0].get("value", "No description available")
            metrics = cve_item.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV2") else {}
            
            # Get CVSS scores
            cvss_v3_score = cvss_v3.get("baseScore", "N/A")
            cvss_v3_severity = cvss_v3.get("baseSeverity", "N/A")
            cvss_v2_score = cvss_v2.get("baseScore", "N/A")
            
            # Get affected products
            configurations = cve_data.get("vulnerabilities", [])[0].get("cve", {}).get("configurations", [])
            affected_products = []
            
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "")
                        if cpe and cpe_match.get("vulnerable", False):
                            parts = cpe.split(":")
                            if len(parts) > 4:
                                vendor = parts[3]
                                product = parts[4]
                                version = parts[5] if len(parts) > 5 else "*"
                                affected_products.append(f"{vendor}:{product}:{version}")
            
            # Get EPSS score if available
            epss_score = "N/A"
            epss_percentile = "N/A"
            if additional_data.get("epss"):
                epss_data = additional_data["epss"]
                epss_score = epss_data.get("epss", "N/A")
                epss_percentile = epss_data.get("percentile", "N/A")
            
            # Get related GitHub repositories if available
            github_repos = []
            if additional_data.get("github") and additional_data["github"].get("related_repositories"):
                github_repos = additional_data["github"]["related_repositories"]
            
            # Prepare CVE summary
            cve_summary = f"""## CVE Analysis: {cve_id}

### Description
{description}

### Severity
- CVSS v3 Score: {cvss_v3_score} ({cvss_v3_severity})
- CVSS v2 Score: {cvss_v2_score}
- EPSS Score: {epss_score} (Percentile: {epss_percentile})

### Affected Products/Dependencies
"""
            
            if affected_products:
                cve_summary += "\n".join([f"- {product}" for product in affected_products])
            else:
                cve_summary += "No specific affected products listed."
                
            # Add GitHub repositories if available
            if github_repos:
                cve_summary += "\n\n### Related GitHub Repositories\n"
                cve_summary += "\n".join([f"- [{repo['name']}]({repo['url']})" for repo in github_repos])
                cve_summary += "\n\nThese repositories may contain additional information, patches, or discussions about this vulnerability."
            
            # If no codebase path is provided, return just the CVE analysis
            if not codebase_path:
                return cve_summary
            
            # Load and analyze the codebase
            documents = self.load_codebase(codebase_path)
            if not documents:
                return cve_summary + "\n\n### Codebase Relevance\nNo codebase documents were loaded for analysis."
            
            # Create a prompt for analyzing the relevance of the CVE to the codebase
            relevance_prompt = PromptTemplate(
                input_variables=["cve_id", "cve_description", "affected_products", "codebase_content"],
                template="""You are a security expert analyzing the relevance of a vulnerability to a codebase.

CVE ID: {cve_id}
CVE Description: {cve_description}
Affected Products/Dependencies: {affected_products}

Codebase content:
{codebase_content}

Based on the information provided, analyze whether this codebase might be affected by the vulnerability.
Consider:
1. Does the codebase use any of the affected dependencies or products?
2. Are there any patterns in the code that match the vulnerability description?
3. What specific files or code sections might be vulnerable?
4. What remediation steps would you recommend?

Provide a detailed analysis with specific references to the codebase where possible.
"""
            )
            
            # Prepare the chain
            chain = LLMChain(llm=self.llm, prompt=relevance_prompt)
            
            # Analyze each document chunk and combine the results
            all_analyses = []
            for i, doc in enumerate(documents[:10]):  # Limit to first 10 documents to avoid token limits
                try:
                    analysis = chain.run({
                        "cve_id": cve_id,
                        "cve_description": description,
                        "affected_products": "\n".join(affected_products),
                        "codebase_content": doc.page_content
                    })
                    all_analyses.append(analysis)
                except Exception as e:
                    print(f"Error analyzing document {i}: {e}")
            
            # Combine all analyses
            if all_analyses:
                # Use the LLM to summarize all analyses
                summary_prompt = PromptTemplate(
                    input_variables=["cve_id", "analyses"],
                    template="""You are a security expert summarizing the relevance of a vulnerability to a codebase.

CVE ID: {cve_id}

Individual file analyses:
{analyses}

Provide a comprehensive summary of whether this codebase is affected by the vulnerability.
Include specific files or code patterns that might be vulnerable and recommended remediation steps.
"""
                )
                
                summary_chain = LLMChain(llm=self.llm, prompt=summary_prompt)
                relevance_summary = summary_chain.run({
                    "cve_id": cve_id,
                    "analyses": "\n\n---\n\n".join(all_analyses)
                })
            else:
                relevance_summary = "No detailed analysis could be performed on the codebase."
            
            # Combine CVE summary and relevance analysis
            return f"{cve_summary}\n\n### Codebase Relevance\n{relevance_summary}"
            
        except Exception as e:
            return f"Error analyzing CVE {cve_id}: {str(e)}"


def get_available_models() -> Dict[str, List[str]]:
    """Get the available AI models based on the API keys in the .env file.

    Returns:
        A dictionary mapping model providers to lists of available models.
    """
    available_models = {}
    
    # Check for OpenAI API key
    if os.getenv("OPENAI_API_KEY"):
        available_models["OpenAI"] = [
            "openai/gpt-3.5-turbo",
            "openai/gpt-4",
            "openai/gpt-4-turbo"
        ]
    
    # Check for Gemini API key
    if os.getenv("GEMINI_API_KEY"):
        available_models["Gemini"] = [
            "gemini/gemini-pro"
        ]
    
    # Check for Mistral API key
    if os.getenv("MISTRAL_API_KEY"):
        available_models["Mistral"] = [
            "mistral/mistral-small",
            "mistral/mistral-medium",
            "mistral/mistral-large"
        ]
    
    # Check for Ollama (no API key needed, just check if base URL is set)
    if os.getenv("OLLAMA_BASE_URL"):
        available_models["Ollama"] = [
            "ollama/llama2",
            "ollama/mistral",
            "ollama/codellama"
        ]
    
    return available_models


def select_model() -> str:
    """Prompt the user to select an AI model from the available options.

    Returns:
        The selected model name.
    """
    available_models = get_available_models()
    
    if not available_models:
        print("No API keys found in .env file. Please add at least one API key.")
        sys.exit(1)
    
    print("Available AI models:")
    all_models = []
    for provider, models in available_models.items():
        print(f"\n{provider}:")
        for i, model in enumerate(models):
            model_index = len(all_models)
            all_models.append(model)
            print(f"  {model_index + 1}. {model}")
    
    while True:
        try:
            choice = int(input("\nSelect a model (enter the number): "))
            if 1 <= choice <= len(all_models):
                return all_models[choice - 1]
            else:
                print(f"Please enter a number between 1 and {len(all_models)}")
        except ValueError:
            print("Please enter a valid number")


def main():
    """Main function to run the CVE Explainer tool."""
    # Load environment variables from .env file
    load_dotenv()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="CVE Explainer Tool")
    parser.add_argument("--cve", type=str, help="CVE identifier (e.g., CVE-2021-44228)")
    parser.add_argument("--path", type=str, help="Path to the codebase to analyze")
    args = parser.parse_args()
    
    # If no CVE ID is provided, prompt the user
    cve_id = args.cve
    if not cve_id:
        cve_id = input("Enter CVE identifier (e.g., CVE-2021-44228): ")
    
    # If no path is provided, use the current directory
    codebase_path = args.path
    if not codebase_path:
        use_current = input("Analyze current directory? (y/n): ").lower()
        if use_current == 'y':
            codebase_path = os.getcwd()
        else:
            codebase_path = input("Enter path to codebase: ")
    
    # Select the AI model to use
    model_name = select_model()
    
    # Initialize the CVE Explainer
    explainer = CVEExplainer(model_name)
    
    # Analyze the CVE
    print(f"\nAnalyzing {cve_id} using {model_name}...\n")
    result = explainer.analyze_cve(cve_id, codebase_path)
    
    # Print the result
    print(result)
    
    # Save the result to a file
    output_file = f"{cve_id.replace('-', '_')}_analysis.md"
    with open(output_file, "w") as f:
        f.write(result)
    
    print(f"\nAnalysis saved to {output_file}")


if __name__ == "__main__":
    main()