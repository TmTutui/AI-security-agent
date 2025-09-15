#!/usr/bin/env python3
"""
AI Security Agent - CVE Explainer

This script analyzes CVEs and their relevance to a codebase using AI models.
"""

import argparse
import os
from dotenv import load_dotenv
from models.model_manager import ModelManager
from data.data_fetcher import DataFetcher
from analysis.cve_analyzer import CVEAnalyzer
from analysis.codebase_analyzer import CodebaseAnalyzer


def main():
    """Main entry point for the CVE Explainer application."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Analyze CVEs and their relevance to a codebase using AI models.")
    parser.add_argument("--cve", type=str, help="CVE identifier (e.g., CVE-2021-44228)")
    parser.add_argument("--codebase", type=str, help="Path to the codebase to analyze")

    parser.add_argument("--temperature", type=float, default=0, help="Temperature for model generation")
    parser.add_argument("--save-analysis", action="store_true", help="Save the detailed analysis to a file")
    parser.add_argument("--interactive", action="store_true", help="Run the explainer in interactive mode")
    args = parser.parse_args()

    # Load environment variables from .env file
    load_dotenv()

    # Initialize the model manager, get available models and select one
    model_manager = ModelManager()
    model_name, model_provider = model_manager.select_model()

    if not model_name or not model_provider:
        print("No suitable model found. Please check your API keys and model availability.")
        return
    
    # Initialize the model
    llm = model_manager.initialize_model(model_name, model_provider, args.temperature)
    if not llm:
        print(f"Failed to initialize model: {model_name}")
        return
    
    # Initialize components
    data_fetcher = DataFetcher()
    cve_analyzer = CVEAnalyzer(llm)
    codebase_analyzer = CodebaseAnalyzer(llm)

    def run_analysis(cve_id, codebase_path, save_analysis_flag):
        # Fetch CVE data
        print(f"Fetching CVE data for {cve_id}...")
        try:
            cve_data = data_fetcher.fetch_cve_data(cve_id)
            additional_data = data_fetcher.fetch_additional_vulnerability_data(cve_id)
        except Exception as e:
            print(f"Error fetching CVE data: {e}")
            return
        
        # Analyze CVE
        print(f"Analyzing CVE {cve_id}...")
        description, severity, affected_products, detailed_analysis = cve_analyzer.analyze_cve(
            cve_id, cve_data, additional_data
        )
        
        # Print CVE analysis
        print(f"\n{'=' * 80}")
        print(f"CVE ID: {cve_id}")
        print(f"{'=' * 80}")
        print(f"Description: {description}")
        print(f"Severity: {severity}")
        print(f"Affected Products:")
        for product in affected_products:
            print(f"  - {product}")
        print("\nDetailed Analysis:")
        print(detailed_analysis)

        if (save_analysis_flag):
            # Save detailed analysis to a file
            output_dir = "analysis_results"
            os.makedirs(output_dir, exist_ok=True)
            output_filename = os.path.join(output_dir, f"{cve_id} - AI analysis.md")
            with open(output_filename, "w") as f:
                f.write(f"# Analysis of {cve_id}\n\n")
                f.write(f"## Description\n{description}\n\n")
                f.write(f"## Severity\n{severity}\n\n")
                f.write(f"## Affected Products\n")
                for product in affected_products:
                    f.write(f"  - {product}\n")
                f.write(f"\n## Detailed AI Analysis\n{detailed_analysis}\n")
            print(f"\nDetailed analysis saved to {output_filename}")
        
        # Analyze codebase if provided
        if codebase_path:
            codebase_name = os.path.basename(codebase_path.rstrip(os.sep))
            print(f"\n{'=' * 80}")
            print(f"Codebase Analysis: {codebase_name} ({codebase_path})")
            print(f"{'=' * 80}")
            
            # Load codebase
            documents = codebase_analyzer.load_codebase(codebase_path)
            if not documents:
                print("Failed to load codebase.")
                return
            
            print(f"\nDocuments uploaded!")
            print(f"Performing relevance analysis on {codebase_name}...")

            # Analyze codebase relevance
            relevance_analysis = codebase_analyzer.analyze_codebase_relevance(
                cve_id, description, affected_products, documents
            )
            
            print(relevance_analysis)

            if (save_analysis_flag):
                output_filename = os.path.join(output_dir, f"{codebase_name} - {cve_id} - AI analysis.md")
                with open(output_filename, "a") as f:
                    f.write(f"# Analysis of {codebase_name} for {cve_id}\n\n")
                    f.write(f"\n## Codebase Relevance Analysis\n{relevance_analysis}\n")
                print(f"\nCodebase analysis saved to {output_filename}")

    if args.interactive or not args.cve:
        cve_input = args.cve
        while not cve_input:
            cve_input = input("Enter CVE ID (e.g., CVE-2021-44228) or 'q' to quit: ")
            if cve_input.lower() == 'q':
                return

        codebase_input = args.codebase
        if not codebase_input:
            codebase_input = input("Enter codebase path (leave blank if none): ")

        run_analysis(cve_input, codebase_input, args.save_analysis)
    else:
        run_analysis(args.cve, args.codebase, args.save_analysis)

if __name__ == "__main__":
    main()