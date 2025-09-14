"""
CVE Analyzer Module

This module handles CVE analysis, including severity calculation and affected products identification.
"""

from typing import Dict, List, Tuple


class CVEAnalyzer:
    """Handles CVE analysis, including severity calculation and affected products identification."""

    def __init__(self, llm):
        """Initialize the CVE Analyzer.
        
        Args:
            llm: The language model to use for analysis.
        """
        self.llm = llm

    def calculate_severity(self, cve_data: Dict) -> str:
        """Calculate the severity of a CVE based on CVSS score.

        Args:
            cve_data: The CVE data dictionary.

        Returns:
            A string representing the severity level.
        """
        try:
            # Extract CVSS data from the CVE data
            vulnerabilities = cve_data.get("vulnerabilities", [])
            if not vulnerabilities:
                return "Unknown"
                
            cve_item = vulnerabilities[0]
            metrics = cve_item.get("cve", {}).get("metrics", {})
            
            # Try to get CVSS V3 score first, then fall back to CVSS V2
            cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            cvss_v2 = metrics.get("cvssMetricV2", [])
            
            if cvss_v3:
                base_score = cvss_v3[0].get("cvssData", {}).get("baseScore")
                if base_score is not None:
                    return self._get_severity_level(base_score)
            
            if cvss_v2:
                base_score = cvss_v2[0].get("cvssData", {}).get("baseScore")
                if base_score is not None:
                    return self._get_severity_level(base_score)
                    
            return "Unknown"
        except Exception as e:
            print(f"Error calculating severity: {e}")
            return "Unknown"
    
    def _get_severity_level(self, base_score: float) -> str:
        """Convert a CVSS base score to a severity level.

        Args:
            base_score: The CVSS base score.

        Returns:
            A string representing the severity level.
        """
        if base_score >= 9.0:
            return "Critical"
        elif base_score >= 7.0:
            return "High"
        elif base_score >= 4.0:
            return "Medium"
        elif base_score > 0.0:
            return "Low"
        else:
            return "None"
    
    def identify_affected_products(self, cve_data: Dict) -> List[str]:
        """Identify products affected by a CVE.

        Args:
            cve_data: The CVE data dictionary.

        Returns:
            A list of affected products.
        """
        affected_products = []
        try:
            vulnerabilities = cve_data.get("vulnerabilities", [])
            if not vulnerabilities:
                return affected_products
                
            cve_item = vulnerabilities[0]
            configurations = cve_item.get("cve", {}).get("configurations", [])
            
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_match = node.get("cpeMatch", [])
                    for cpe in cpe_match:
                        if cpe.get("vulnerable", False):
                            cpe_uri = cpe.get("criteria", "")
                            if cpe_uri:
                                # Extract product information from CPE URI
                                parts = cpe_uri.split(":")
                                if len(parts) >= 5:
                                    vendor = parts[3]
                                    product = parts[4]
                                    version = parts[5] if len(parts) > 5 else "*"
                                    affected_products.append(f"{vendor}:{product}:{version}")
        except Exception as e:
            print(f"Error identifying affected products: {e}")
            
        return affected_products
    
    def analyze_cve(self, cve_id: str, cve_data: Dict, additional_data: Dict) -> Tuple[str, str, List[str], str]:
        """Analyze a CVE and generate a comprehensive report.

        Args:
            cve_id: The CVE identifier.
            cve_data: The CVE data dictionary.
            additional_data: Additional vulnerability data.

        Returns:
            A tuple containing (description, severity, affected_products, detailed_analysis).
        """
        # Extract CVE description
        description = ""
        try:
            vulnerabilities = cve_data.get("vulnerabilities", [])
            if vulnerabilities:
                cve_item = vulnerabilities[0]
                description = cve_item.get("cve", {}).get("descriptions", [])[0].get("value", "")
        except Exception as e:
            print(f"Error extracting description: {e}")
            description = "Description not available"
        
        # Calculate severity
        severity = self.calculate_severity(cve_data)
        
        # Identify affected products
        affected_products = self.identify_affected_products(cve_data)
        
        # Generate detailed analysis using LLM
        detailed_analysis = self._generate_detailed_analysis(cve_id, description, severity, affected_products, additional_data)
        
        return description, severity, affected_products, detailed_analysis
    
    def _generate_detailed_analysis(self, cve_id: str, description: str, severity: str, affected_products: List[str], additional_data: Dict) -> str:
        """Generate a detailed analysis of a CVE using the language model.

        Args:
            cve_id: The CVE identifier.
            description: The CVE description.
            severity: The severity level.
            affected_products: List of affected products.
            additional_data: Additional vulnerability data.

        Returns:
            A string containing the detailed analysis.
        """
        # Prepare the prompt for the language model
        prompt = f"""
            You are a security expert analyzing a vulnerability.

            CVE ID: {cve_id}
            Description: {description}
            Severity: {severity}
            Affected Products: {', '.join(affected_products) if affected_products else 'Not specified'}

            Additional Data:
            {additional_data}

            Please provide a detailed analysis of this vulnerability, including:
            1. A clear explanation of the vulnerability in simple terms
            2. The potential impact if exploited
            3. Common attack vectors
            4. Recommended mitigation strategies
            5. Any notable exploits or incidents related to this vulnerability
        """
        
        try:
            # Generate the analysis using the language model
            analysis = self.llm.invoke(prompt).content
            return analysis
        except Exception as e:
            print(f"Error generating detailed analysis: {e}")
            return "Detailed analysis could not be generated."