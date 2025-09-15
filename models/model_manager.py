"""
Model Manager Module

This module handles the initialization, selection, and management of AI models
for the CVE Explainer tool.
"""

import os
import sys
import openai
import google.generativeai as genai
from mistralai import Mistral
from typing import Dict, List


class ModelManager:
    """Manages AI models for the CVE Explainer tool."""

    def __init__(self):
        """Initialize the Model Manager."""
        # Initialize API keys and clients
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        if self.openai_api_key is None:
            print("OpenAI API key not found. OpenAI models will not be available.")

        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        if self.gemini_api_key:
            genai.configure(api_key=self.gemini_api_key)
        else:
            print("Gemini API key not found. Gemini models will not be available.")

        self.mistral_api_key = os.getenv("MISTRAL_API_KEY")
        self.mistral_client = Mistral(api_key=self.mistral_api_key) if self.mistral_api_key else None
        if self.mistral_api_key is None:
            print("Mistral API key not found. Mistral models will not be available.")

        self.ollama_base_url = os.getenv("OLLAMA_BASE_URL")
        self.ollama_client = None
        if self.ollama_base_url:
            try:
                import ollama
                self.ollama_client = ollama
            except ImportError:
                print("Ollama client not installed. Please install it with 'pip install ollama'")
            except Exception as e:
                print(f"Error initializing Ollama client: {e}")

    def initialize_model(self, model_name: str, provider: str, temperature: float = 0):
        """Initialize the specified AI model.

        Args:
            model_name: The name of the model to initialize.

        Returns:
            An initialized LLM instance.

        Raises:
            ValueError: If the model is not supported or the API key is missing.
        """
        if provider == "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model_name=model_name, temperature=temperature, api_key=self.openai_api_key)
        
        elif provider == "gemini":
            from langchain_google_genai import ChatGoogleGenerativeAI
            return ChatGoogleGenerativeAI(model=model_name, temperature=temperature, google_api_key=self.gemini_api_key)
        
        elif provider == "mistral":
            from langchain_mistralai.chat_models import ChatMistralAI
            return ChatMistralAI(model=model_name, temperature=temperature, api_key=self.mistral_api_key)
        
        elif provider == "ollama":
            from langchain_community.llms import Ollama
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            return Ollama(model=model_name, base_url=base_url)
        
        else:
            raise ValueError(f"Unsupported model: {model_name}")

    def get_available_models(self) -> Dict[str, List[str]]:
        """Returns a dictionary of available models for each provider."""
        available_models = {
            "openai": [],
            "gemini": [],
            "mistral": [],
            "ollama": [],
        }

        if self.openai_api_key:
            openai_client = openai.OpenAI(api_key=self.openai_api_key)
            
            try:
                openai_models = openai_client.models.list()
                for model in openai_models.data:
                    # Filter for chat and completion models, excluding embedding and other non-chat models
                    if any(keyword in model.id for keyword in ["gpt", "davinci", "babbage", "ada"]):
                        available_models["openai"].append(model.id)
            except Exception as e:
                print(f"Error fetching OpenAI models: {e}")

        if self.gemini_api_key:
            try:
                for model in genai.list_models():
                    # Filter for language models that support 'generateContent' and produce text output
                    if 'generateContent' in model.supported_generation_methods and \
                       (hasattr(model, 'output_types') and 'text' in model.output_types or not hasattr(model, 'output_types')):
                        available_models["gemini"].append(model.name)
            except Exception as e:
                print(f"Error fetching Gemini models: {e}")

        if self.mistral_api_key:
            if self.mistral_client:
                try:
                    mistral_models = self.mistral_client.models.list()
                    for model in mistral_models.data:
                        # Filter for language models, excluding embedding and moderation models
                        if any(keyword in model.id for keyword in ["mistral", "magistral", "codestral", "devstral", "nemo"]) and \
                           not any(keyword in model.id for keyword in ["embed", "moderation"]):
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

    def select_model(self) -> tuple[str, str]:
        """Prompt the user to select an AI model from the available options.

        Returns:
            The selected model name and its provider as a tuple.
        """
        available_models = self.get_available_models()
        
        if not any(models for models in available_models.values()):
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
            selection = input("Enter the desired model (e.g., gpt-4o, gemini-2.5-flash, mistral-medium, llama2): ").strip()
            # Check if the selected model is in any of the provider's lists
            found = False
            for provider, models in available_models.items():
                if selection in models:
                    return selection, provider
            
            print("Invalid selection. Please choose from the available models.")