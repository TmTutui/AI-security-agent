"""
Codebase Analyzer Module

This module handles loading and analyzing codebases for CVE relevance.
"""

from pathlib import Path
from typing import List
from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import TextLoader, DirectoryLoader
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
import inspect


class CodebaseAnalyzer:
    """Handles loading and analyzing codebases for CVE relevance."""

    def __init__(self, llm):
        """Initialize the Codebase Analyzer.
        
        Args:
            llm: The language model to use for analysis.
        """
        self.llm = llm

        # arbitrary values, may need some tweaking
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=4000,
            chunk_overlap=200,
            length_function=len,
        )

        ignored_formats = [
            "*.pdf",
            "*.jpeg",
            "*.jpg",
            "*.png",
            "*.gif",
            "*.svg",
            "*.ico",
            "*.avif",
            "*.webp",
            "*.mp4",
            "*.mov",
            "*.avi",
            "*.wmv",
            "*.flv",
            "*.mkv",
            "*.mp3",
            "*.wav",
            "*.aac",
            "*.flac",
            "*.docx",
            "*.xlsx",
            "*.pptx",
            "*.zip",
            "*.tar.gz",
            "*.tar",
            "*.gz",
            "*.7z",
            "*.rar",
            "*.jar",
            "*.war",
            "*.ear",
            "*.dll",
            "*.so",
            "*.dylib",
            "*.exe",
            "*.bin",
            "*.iso",
            "*.img",
            "*.vmdk",
            "*.vdi",
            "*.vhd",
            "*.vhdx",
            "*.hdd",
            "*.hdf",
            "*.raw",
            "*.qcow2",
            "*.vbox",
            "*.vmx",
            "*.vmsd",
            "*.vmsn",
            "*.vmss",
            "*.vmem",
            "*.vmem",
            "*.vmem",
        ]
        ignored_path = [
            "**/.git/**",
            "**/node_modules/**",
            "**/__pycache__/**",
            "**/venv/**",
            "**/env/**",
            "**/dist/**",
            "**/build/**",
            "**/target/**",
            "**/out/**",
            "**/bin/**",
            "**/obj/**",
            "**/tmp/**",
            "**/cache/**",
            "**/logs/**",
            "**/tmp/**",
            "**/example/**",
            "**/examples/**",
            "**/demo/**",
            "**/demos/**",
            "**/public/**",
        ]

        self.ignored_files = ignored_formats + ignored_path

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
                # Load allowed files from the directory
                loader = DirectoryLoader(
                    path,
                    exclude=self.ignored_files,
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

    def analyze_codebase_relevance(self, cve_id: str, description: str, affected_products: List[str], documents: List[Document]) -> str:
        """Analyze the relevance of a CVE to a codebase.

        Args:
            cve_id: The CVE identifier.
            description: The CVE description.
            affected_products: List of affected products.
            documents: List of Document objects containing the codebase content.

        Returns:
            A string containing the analysis results.
        """
        if not documents:
            return "No codebase documents were loaded for analysis."
        
        # Create a prompt for analyzing the relevance of the CVE to the codebase
        relevance_prompt = PromptTemplate(
            input_variables=["cve_id", "cve_description", "affected_products", "codebase_content"],
            template=inspect.cleandoc("""
                You are a security expert analyzing the relevance of a vulnerability to a codebase.

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
            """)
        )
        
        # Prepare the chain
        chain = relevance_prompt | self.llm
        
        # Analyze each document chunk and combine the results
        all_analyses = []
        for i, doc in enumerate(documents[:10]):  # Limit to first 10 documents to avoid token limits
            try:
                analysis = chain.invoke({
                    "cve_id": cve_id,
                    "cve_description": description,
                    "affected_products": "\n".join(affected_products),
                    "codebase_content": doc.page_content
                })
                all_analyses.append(analysis.content)
            except Exception as e:
                print(f"Error analyzing document {i}: {e}")
        
        # Combine all analyses
        if all_analyses:
            # Use the LLM to summarize all analyses
            summary_prompt = PromptTemplate(
                input_variables=["cve_id", "analyses"],
                template=inspect.cleandoc("""
                    You are a security expert summarizing the relevance of a vulnerability to a codebase.

                    CVE ID: {cve_id}

                    Individual file analyses:
                    {analyses}

                    Provide a comprehensive summary of whether this codebase is affected by the vulnerability.
                    Include specific files or code patterns that might be vulnerable and recommended remediation steps.
                """)
            )
            
            summary_chain = summary_prompt | self.llm
            relevance_summary = summary_chain.invoke({
                "cve_id": cve_id,
                "analyses": "\n\n---\n\n".join(all_analyses)
            })
            return relevance_summary.content
        else:
            return "No detailed analysis could be performed on the codebase."