#!/usr/bin/env python3
"""
CVE Explainer Tool

A tool to help security engineers understand vulnerability reports (CVE).
This script uses a modular architecture to interact with various AI models to provide
detailed information about CVEs and their relevance to a codebase.
"""

import os
import argparse

# Load environment variables
from dotenv import load_dotenv

# Import modular components
from models.model_manager import ModelManager
from data.data_fetcher import DataFetcher
from analysis.cve_analyzer import CVEAnalyzer
from analysis.codebase_analyzer import CodebaseAnalyzer


class CVEExplainer:
    """CVE Explainer Tool to analyze vulnerabilities and their relevance to a codebase."""

    def __init__(self, model_name: str):
        """Initialize the CVE Explainer with the specified model.

        Args:
            model_name: The name of the AI model to use.
        """
        self.model_name = model_name
        
        # Initialize the model manager
        self.model_manager = ModelManager()
        
        # Initialize the model
        self.llm = self.model_manager.initialize_model(model_name)
        if not self.llm:
            raise ValueError(f"Failed to initialize model: {model_name}")
            
        # Initialize components
        self.data_fetcher = DataFetcher(self.llm)
        self.cve_analyzer = CVEAnalyzer(self.llm)
        self.codebase_analyzer = CodebaseAnalyzer(self.llm)

    # This method is now handled by ModelManager
    def _initialize_model(self):
        """Initialize the specified AI model (legacy method, now handled by ModelManager)."""
        return self.model_manager.initialize_model(self.model_name)

    def fetch_cve_data(self, cve_id: str) -> Dict:
        """Fetch CVE data from the NVD API.

        Args:
            cve_id: The CVE identifier (e.g., CVE-2021-44228).

        Returns:
            A dictionary containing the CVE data.

        Raises:
            Exception: If the CVE data cannot be fetched.
        """
        return self.data_fetcher.fetch_cve_data(cve_id)
            
    def fetch_additional_vulnerability_data(self, cve_id: str) -> Dict:
        """Fetch additional vulnerability data from multiple sources.
        
        Args:
            cve_id: The CVE identifier (e.g., CVE-2021-44228).
            
        Returns:
            A dictionary containing additional vulnerability data.
        """
        return self.data_fetcher.fetch_additional_vulnerability_data(cve_id)

    def load_codebase(self, path: str) -> List[Document]:
        """Load the codebase from the specified path.

        Args:
            path: The path to the codebase.

        Returns:
            A list of Document objects containing the codebase content.
        """
        return self.codebase_analyzer.load_codebase(path)

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
            
            # Use the CVE analyzer to analyze the CVE
            description, severity, affected_products, detailed_analysis = self.cve_analyzer.analyze_cve(
                cve_id, cve_data, additional_data
            )
                                # If a codebase path is provided, analyze its relevance to the CVE
            if codebase_path:
                # Load the codebase
                documents = self.load_codebase(codebase_path)
                if not documents:
                    return "Failed to load codebase."
                
                # Analyze codebase relevance
                relevance_analysis = self.codebase_analyzer.analyze_codebase_relevance(
                    cve_id, description, affected_products, documents
                )
                
                # Combine the CVE analysis and codebase relevance analysis
                return f"""
                {cve_id}
                Description: {description}
                Severity: {severity}
                Affected Products: {', '.join(affected_products) if affected_products else 'None'}
                
                Detailed Analysis:
                {detailed_analysis}
                
                Codebase Relevance Analysis:
                {relevance_analysis}
                """
            else:
                # Return just the CVE analysis
                return f"""
                
                Description: {description}
                Severity: {severity}
                Affected Products: {', '.join(affected_products) if affected_products else 'None'}
                
                Detailed Analysis:
                {detailed_analysis}
                """
        except Exception as e:
            return f"Error analyzing CVE: {e}"

    def get_available_models(self):
        """Get available models from the model manager.

        Returns:
            A dictionary of available models by provider.
        """
        return self.model_manager.get_available_models()

    def select_model(self, available_models, provider=None, model_name=None):
        """Select a model to use for analysis.

        Args:
            available_models: A dictionary of available models by provider.
            provider: The provider to use (e.g., "openai", "gemini", "mistral", "ollama").
            model_name: The specific model to use.

        Returns:
            The selected model name.
        """
        return self.model_manager.select_model(available_models, provider, model_name)


def main():
    """Main entry point for the CVE Explainer application."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Analyze CVEs and their relevance to a codebase using AI models.")
    parser.add_argument("--cve", type=str, help="CVE identifier (e.g., CVE-2021-44228)")
    parser.add_argument("--codebase", type=str, help="Path to the codebase to analyze")
    parser.add_argument("--model", type=str, help="Specific model to use for analysis")
    parser.add_argument("--provider", type=str, choices=["openai", "gemini", "mistral", "ollama"], 
                        help="Model provider to use")
    args = parser.parse_args()

    # Initialize the model manager
    model_manager = ModelManager()
    
    # Get available models and select one
    available_models = model_manager.get_available_models()
    selected_model = model_manager.select_model(available_models, args.provider, args.model)
    
    if not selected_model:
        print("No suitable model found. Please check your API keys and model availability.")
        return
    
    # Initialize the CVE Explainer
    cve_explainer = CVEExplainer(selected_model)
    
    # Analyze the CVE
    analysis = cve_explainer.analyze_cve(args.cve, args.codebase)
    
    # Print the analysis
    print(analysis)


if __name__ == "__main__":
    # Load environment variables
    load_dotenv()
    main()


            
                    
                        
                            
                    
               
            
                    
           
            if self.mistral_client:
                try:
                    mistral_models = self.mistral_client.models.list()
                    for model in mistral_models.data:
                        available_models["mistral"].append(model.id)
                except Exception as e:
                    print(f"Error fetching Mistral models: {e}")
            else:
                print("Mistral API key is set, but client not initialized. Check API key validity.")

        if self.ollama_base_url and self.ollama_client:
            try:
                available_models["ollama"] = [model['name'] for model in self.ollama_client.list()['models']]
            except Exception as e:
                print(f"Error fetching Ollama models: {e}")

        return available_models


    def select_model(self) -> str:
        """Prompt the user to select an AI model from the available options.

        Returns:
            The selected model name.
        """
        available_models = self.get_available_models()
        
        if not available_models:
            print("No API keys found in .env file. Please add at least one API key.")
            sys.exit(1)

        print("\nAvailable AI Models:")
        model_options = []
        for provider, models in available_models.items():
            for model in models:
                # For Ollama, we don't prepend 'ollama/' as the model name itself is sufficient
                if provider == "ollama":
                    model_options.append(model)
                    print(f"  - {model}")
                else:
                    model_options.append(model)
                    print(f"  - {model} ({provider})")

        while True:
            selection = input("Enter the desired model (e.g., gpt-4o, gemini-pro, llama2): ").strip()
            # Check if the selected model is in any of the provider's lists
            found = False
            for provider, models in available_models.items():
                if selection in models:
                    found = True
                    break
            
            if found:
                return selection
            else:
                print("Invalid selection. Please choose from the available models.")


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
    
    explainer = CVEExplainer("initial_model_placeholder") # Initialize with a placeholder
    model_name = explainer.select_model()
    explainer.model_name = model_name # Update the model name after selection
    explainer.llm = explainer._initialize_model() # Re-initialize LLM with selected model
    
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