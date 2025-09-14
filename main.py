#!/usr/bin/env python3
"""
AI Security Agent - CVE Explainer

This script analyzes CVEs and their relevance to a codebase using AI models.
"""

import argparse
import os
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
    args = parser.parse_args()

    # Initialize the model manager, get available models and select one
    model_manager = ModelManager()
    selected_model = model_manager.select_model()
    
    if not selected_model:
        print("No suitable model found. Please check your API keys and model availability.")
        return
    
    # Initialize the model
    llm = model_manager.initialize_model(selected_model, args.temperature)
    if not llm:
        print(f"Failed to initialize model: {selected_model}")
        return
    
    # Initialize components
    data_fetcher = DataFetcher()
    cve_analyzer = CVEAnalyzer(llm)
    codebase_analyzer = CodebaseAnalyzer(llm)
    
    # Fetch CVE data
    try:
        cve_data = data_fetcher.fetch_cve_data(args.cve)
        additional_data = data_fetcher.fetch_additional_vulnerability_data(args.cve)
    except Exception as e:
        print(f"Error fetching CVE data: {e}")
        return
    
    # Analyze CVE
    description, severity, affected_products, detailed_analysis = cve_analyzer.analyze_cve(
        args.cve, cve_data, additional_data
    )
    
    # Print CVE analysis
    print(f"\n{'=' * 80}")
    print(f"CVE ID: {args.cve}")
    print(f"{'=' * 80}")
    print(f"Description: {description}")
    print(f"Severity: {severity}")
    print(f"Affected Products:")
    for product in affected_products:
        print(f"  - {product}")
    print("\nDetailed Analysis:")
    print(detailed_analysis)

    if (args.save_analysis):
        # Save detailed analysis to a file
        output_dir = "analysis_results"
        os.makedirs(output_dir, exist_ok=True)
        output_filename = os.path.join(output_dir, f"{args.cve} - AI analysis.md")
        with open(output_filename, "w") as f:
            f.write(f"# Analysis of {args.cve}\n\n")
            f.write(f"## Description\n{description}\n\n")
            f.write(f"## Severity\n{severity}\n\n")
            f.write(f"## Affected Products\n")
            for product in affected_products:
                f.write(f"  - {product}\n")
            f.write(f"\n## Detailed AI Analysis\n{detailed_analysis}\n")
        print(f"\nDetailed analysis saved to {output_filename}")
    
    # Analyze codebase if provided
    if args.codebase:
        codebase_name = os.path.basename(args.codebase.rstrip(os.sep))
        print(f"\n{'=' * 80}")
        print(f"Codebase Analysis: {codebase_name} ({args.codebase})")
        print(f"{'=' * 80}")
        
        # Load codebase
        documents = codebase_analyzer.load_codebase(args.codebase)
        if not documents:
            print("Failed to load codebase.")
            return
        
        # Analyze codebase relevance
        relevance_analysis = codebase_analyzer.analyze_codebase_relevance(
            args.cve, description, affected_products, documents
        )
        
        print(relevance_analysis)

        if (args.save_analysis):
            output_filename = os.path.join(output_dir, f"{codebase_name} - {args.cve} - AI analysis.md")
            with open(output_filename, "a") as f:
                f.write(f"# Analysis of {codebase_name} for {args.cve}\n\n")
                f.write(f"\n## Codebase Relevance Analysis\n{relevance_analysis}\n")
            print(f"\nCodebase analysis saved to {output_filename}")

if __name__ == "__main__":
    main()