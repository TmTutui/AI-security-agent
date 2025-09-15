# CVE Explainer Tool

A security agent tool to help security engineers understand vulnerability reports (CVE) and their relevance to a codebase.

## Features

- Accepts a CVE identifier as input
- Fetches comprehensive vulnerability information from multiple sources:
  - National Vulnerability Database (NVD)
  - MITRE CVE database
  - Exploit Prediction Scoring System (EPSS)
  - GitHub repositories related to the vulnerability
- Analyzes the relevance of the vulnerability to a specified codebase
- Supports multiple AI models (OpenAI, Google Gemini, Mistral AI, and Ollama)
- Provides detailed output including:
  - CVE description and severity
  - CVSS scores and EPSS exploit probability
  - Affected dependencies and products
  - Related GitHub repositories with patches or discussions
  - Relevance to the codebase
  - Potential vulnerable files or code patterns
  - Recommended remediation steps

## Installation

### Prerequisites

- Python 3.8 or higher
- API keys for the LLM models of choice (or Ollama running locally):
  - OpenAI
  - Google Gemini
  - Mistral AI
  - Ollama

### Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/AI-security-agent.git
cd AI-security-agent
```

2. Create a virtual environment and activate it:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your API keys:

```bash
cp .env.example .env
```

Then edit the `.env` file and add your API keys for the models you want to use.

## Usage

### Basic Usage

Run the script with a CVE identifier and optionally a path to the codebase:

```bash
python cve_explainer.py --cve CVE-2021-44228 --path /path/to/your/codebase
```

If you don't provide the arguments, the script will prompt you for them interactively.

### Interactive Mode

Simply run the script without arguments:

```bash
python cve_explainer.py
```

The script will prompt you for:
1. A CVE identifier
2. A path to the codebase (or use the current directory)
3. Which AI model to use (based on available API keys in your `.env` file)

### Output

The analysis results will be displayed in the terminal and also saved to a Markdown file named `{CVE_ID}_analysis.md` in the current directory.

## Design Rationale

### Technology Choices

- **Python**: Chosen for its rich ecosystem of security and AI libraries, as well as its readability and ease of use.
- **LangChain**: Provides a flexible framework for working with different language models and creating chains of operations for complex tasks. I also had previous experience with this library, which helped me speed up development
- **Multiple AI Model Support**: Different models have different strengths and cost structures. Supporting multiple models gives users flexibility.
- **NVD API**: The National Vulnerability Database provides comprehensive and up-to-date information about CVEs.

### Architecture

The tool follows a modular design:

1. **CVE Data Retrieval**: Fetches vulnerability data from the NVD API.
2. **Codebase Analysis**: Loads and processes the codebase, splitting it into manageable chunks.
3. **AI Analysis**: Uses LangChain to create prompts for the AI models to analyze the relevance of the CVE to the codebase.
4. **Result Aggregation**: Combines individual analyses into a comprehensive report.

### Security Considerations

- API keys are stored in a `.env` file which is excluded from version control via `.gitignore`.
- The tool only analyzes local files and does not transmit your codebase to external services (beyond what the AI API requires).
- When using Ollama, all processing can be done locally for sensitive codebases.

## Limitations

- The tool's analysis is only as good as the AI model being used.
- Large codebases may be only partially analyzed due to token limits of AI models.
- The tool focuses on known vulnerabilities (CVEs) and cannot detect novel security issues.
- Dependency detection is based on code analysis rather than package manager files, which may lead to false negatives.
- The tool does not provide remediation advice beyond flagging potential vulnerabilities.
- The tool was not tested with OpenAI and Ollama models.
- `exclude` of `DirectoryLoader` in `load_codebase` method is not working as expected (not excluding everything that it should).
