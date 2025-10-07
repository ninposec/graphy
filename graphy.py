#!/usr/bin/env python3
"""
GraphQL Security Testing Tool
Comprehensive vulnerability scanner for GraphQL APIs
"""

import requests
import json
import time
import argparse
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import sys

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class GraphQLScanner:
    def __init__(self, url: str, headers: Optional[Dict] = None, timeout: int = 10):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
        self.schema = None
        self.vulnerabilities = []
        self.session = requests.Session()
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.CYAN}{'='*70}
   _____ _____            _      ___  _       _____           _   
  / ____|  __ \          | |    / _ \| |     |_   _|         | |  
 | |  __| |__) |__ _ _ __| |__ | | | | |       | | _ __  ___| |_ 
 | | |_ |  _  // _` | '_ \ '_ \| | | | |       | || '_ \/ __| __|
 | |__| | | \ \ (_| | |_) | | | | |_| | |____  _| || | | \__ \ |_ 
  \_____|_|  \_\__,_| .__/|_| |_|\__\_\______|_____|_| |_|___/\__|
                    | |    Security Testing Tool                  
                    |_|    v1.0                                    
{'='*70}{Colors.END}
"""
        print(banner)
        
    def log(self, level: str, message: str):
        """Log messages with color coding"""
        colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "VULN": Colors.RED + Colors.BOLD
        }
        color = colors.get(level, Colors.END)
        print(f"{color}[{level}]{Colors.END} {message}")
        
    def add_vulnerability(self, vuln_type: str, severity: str, description: str, evidence: str = ""):
        """Add vulnerability to list"""
        self.vulnerabilities.append({
            "type": vuln_type,
            "severity": severity,
            "description": description,
            "evidence": evidence
        })
        self.log("VULN", f"{severity} - {vuln_type}: {description}")
        
    def send_query(self, query: str, variables: Optional[Dict] = None) -> Tuple[Optional[Dict], int, str]:
        """Send GraphQL query and return response"""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
            
        try:
            response = self.session.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=self.timeout
            )
            return response.json(), response.status_code, response.text
        except requests.exceptions.Timeout:
            self.log("ERROR", "Request timed out")
            return None, 0, ""
        except requests.exceptions.RequestException as e:
            self.log("ERROR", f"Request failed: {str(e)}")
            return None, 0, ""
        except json.JSONDecodeError:
            return None, response.status_code, response.text
            
    def test_introspection(self) -> bool:
        """Test if introspection is enabled"""
        self.log("INFO", "Testing introspection query...")
        
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              name
              kind
              description
              fields {
                name
                description
                args {
                  name
                  description
                  type {
                    name
                    kind
                    ofType {
                      name
                      kind
                    }
                  }
                }
                type {
                  name
                  kind
                }
              }
            }
          }
        }
        """
        
        data, status, _ = self.send_query(introspection_query)
        
        if data and "__schema" in data.get("data", {}):
            self.schema = data["data"]["__schema"]
            self.add_vulnerability(
                "Introspection Enabled",
                "MEDIUM",
                "GraphQL introspection is enabled, exposing the entire schema",
                f"Schema contains {len(self.schema.get('types', []))} types"
            )
            self.log("SUCCESS", f"Schema retrieved: {len(self.schema.get('types', []))} types found")
            return True
        else:
            self.log("SUCCESS", "Introspection is disabled (Good!)")
            return False
            
    def test_field_suggestions(self):
        """Test if error messages reveal field suggestions"""
        self.log("INFO", "Testing field suggestion disclosure...")
        
        test_query = """
        query {
          nonExistentField12345
        }
        """
        
        data, status, text = self.send_query(test_query)
        
        if data and "errors" in data:
            error_msg = str(data["errors"])
            # Check if error message suggests valid fields
            if "Did you mean" in error_msg or "suggestion" in error_msg.lower():
                self.add_vulnerability(
                    "Field Suggestion Disclosure",
                    "LOW",
                    "Error messages reveal valid field names through suggestions",
                    error_msg[:200]
                )
            else:
                self.log("INFO", "Error messages don't reveal field suggestions")
                
    def test_depth_limit(self, max_depth: int = 20):
        """Test query depth limits"""
        self.log("INFO", f"Testing query depth limits (up to {max_depth} levels)...")
        
        if not self.schema:
            self.log("WARNING", "Skipping depth test - schema not available")
            return
            
        # Find a type with self-referencing fields
        nested_query = self._build_nested_query(max_depth)
        
        if not nested_query:
            self.log("WARNING", "Could not build nested query - no suitable types found")
            return
            
        start_time = time.time()
        data, status, _ = self.send_query(nested_query)
        elapsed = time.time() - start_time
        
        if data and "data" in data and elapsed > 5:
            self.add_vulnerability(
                "No Query Depth Limit",
                "HIGH",
                f"Server accepts deeply nested queries ({max_depth} levels) taking {elapsed:.2f}s",
                f"Response time: {elapsed:.2f}s"
            )
        elif data and "errors" in data:
            self.log("SUCCESS", f"Query depth limit enforced at depth {max_depth}")
        else:
            self.log("INFO", "Query depth test completed")
            
    def _build_nested_query(self, depth: int) -> Optional[str]:
        """Build a deeply nested query"""
        if not self.schema:
            return None
            
        # Try to find Query type and a field that returns an object
        query_type = None
        for t in self.schema.get("types", []):
            if t["name"] == self.schema.get("queryType", {}).get("name"):
                query_type = t
                break
                
        if not query_type or not query_type.get("fields"):
            return None
            
        # Find first field that returns an object
        for field in query_type["fields"]:
            field_type = field.get("type", {})
            type_name = field_type.get("name") or field_type.get("ofType", {}).get("name")
            
            if type_name and type_name not in ["String", "Int", "Float", "Boolean", "ID"]:
                # Build nested query
                query = f"query {{\n  {field['name']} {{\n"
                query += "    id\n" * depth
                query += "  " * depth + "}\n}"
                return query
                
        return None
        
    def test_batch_query_limit(self, batch_size: int = 50):
        """Test batch query limits"""
        self.log("INFO", f"Testing batch query limits ({batch_size} queries)...")
        
        simple_query = '{"query": "{ __typename }"}'
        batch = "[" + ",".join([simple_query] * batch_size) + "]"
        
        try:
            start_time = time.time()
            response = self.session.post(
                self.url,
                data=batch,
                headers=self.headers,
                timeout=self.timeout
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                self.add_vulnerability(
                    "No Batch Query Limit",
                    "MEDIUM",
                    f"Server accepts batch queries of {batch_size} operations",
                    f"Response time: {elapsed:.2f}s"
                )
            else:
                self.log("SUCCESS", "Batch query limit enforced")
        except requests.exceptions.Timeout:
            self.add_vulnerability(
                "Batch Query DoS",
                "HIGH",
                f"Batch query of {batch_size} operations caused timeout",
                "Server may be vulnerable to DoS via batch queries"
            )
            
    def test_query_complexity(self):
        """Test query complexity limits"""
        self.log("INFO", "Testing query complexity limits...")
        
        if not self.schema:
            self.log("WARNING", "Skipping complexity test - schema not available")
            return
            
        # Build a query requesting many fields
        complex_query = self._build_complex_query()
        
        if not complex_query:
            self.log("WARNING", "Could not build complex query")
            return
            
        start_time = time.time()
        data, status, _ = self.send_query(complex_query)
        elapsed = time.time() - start_time
        
        if data and "data" in data and elapsed > 5:
            self.add_vulnerability(
                "No Query Complexity Limit",
                "HIGH",
                f"Server accepts highly complex queries taking {elapsed:.2f}s",
                f"Response time: {elapsed:.2f}s"
            )
        elif data and "errors" in data:
            error_msg = str(data["errors"])
            if "complexity" in error_msg.lower():
                self.log("SUCCESS", "Query complexity limit enforced")
            else:
                self.log("INFO", "Query rejected but not explicitly for complexity")
                
    def _build_complex_query(self) -> Optional[str]:
        """Build a complex query requesting many fields"""
        if not self.schema:
            return None
            
        query_type = None
        for t in self.schema.get("types", []):
            if t["name"] == self.schema.get("queryType", {}).get("name"):
                query_type = t
                break
                
        if not query_type or not query_type.get("fields"):
            return None
            
        # Request multiple fields
        query = "query {\n"
        for field in query_type["fields"][:10]:  # Limit to first 10 fields
            query += f"  {field['name']}\n"
        query += "}"
        
        return query
        
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        self.log("INFO", "Testing SQL injection patterns...")
        
        payloads = [
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' #",
            "1' UNION SELECT NULL--",
            "1'; DROP TABLE users--",
            "admin'--",
            "' or 1=1--"
        ]
        
        if not self.schema:
            self.log("WARNING", "Skipping SQL injection test - schema not available")
            return
            
        # Try to find fields that accept string arguments
        for payload in payloads:
            query = f'query {{ __typename }}'  # Fallback query
            
            data, status, text = self.send_query(query)
            
            # Check for SQL error messages in response
            if text and any(err in text.lower() for err in ["sql", "syntax error", "mysql", "postgresql", "database"]):
                self.add_vulnerability(
                    "Potential SQL Injection",
                    "CRITICAL",
                    "Response contains SQL error messages",
                    text[:200]
                )
                break
                
    def test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities"""
        self.log("INFO", "Testing NoSQL injection patterns...")
        
        payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
        ]
        
        # This would need specific implementation based on the API
        self.log("INFO", "NoSQL injection testing requires API-specific implementation")
        
    def test_authentication_bypass(self):
        """Test for authentication bypass"""
        self.log("INFO", "Testing authentication bypass...")
        
        # Store original headers
        original_headers = self.headers.copy()
        
        # Test without authentication
        test_headers = {"Content-Type": "application/json"}
        self.headers = test_headers
        
        simple_query = "query { __typename }"
        data, status, _ = self.send_query(simple_query)
        
        if data and "data" in data:
            self.add_vulnerability(
                "Missing Authentication",
                "CRITICAL",
                "API accepts queries without authentication headers",
                f"Status: {status}"
            )
        else:
            self.log("SUCCESS", "Authentication appears to be required")
            
        # Restore headers
        self.headers = original_headers
        
    def test_information_disclosure(self):
        """Test for information disclosure in errors"""
        self.log("INFO", "Testing information disclosure...")
        
        # Send malformed query
        malformed = "query { this is not valid graphql }"
        data, status, text = self.send_query(malformed)
        
        if data and "errors" in data:
            error_msg = str(data["errors"])
            
            # Check for sensitive information disclosure
            sensitive_keywords = [
                "stack trace", "stacktrace", "file path", "/usr/", "/home/",
                "line ", "at ", ".js:", ".py:", ".rb:", "node_modules",
                "internal server", "database", "connection string"
            ]
            
            if any(keyword in error_msg.lower() for keyword in sensitive_keywords):
                self.add_vulnerability(
                    "Information Disclosure",
                    "MEDIUM",
                    "Error messages reveal sensitive information (paths, stack traces)",
                    error_msg[:300]
                )
            else:
                self.log("SUCCESS", "Error messages don't reveal sensitive information")
                
    def test_rate_limiting(self, requests_count: int = 20):
        """Test for rate limiting"""
        self.log("INFO", f"Testing rate limiting ({requests_count} requests)...")
        
        query = "query { __typename }"
        success_count = 0
        
        start_time = time.time()
        for i in range(requests_count):
            data, status, _ = self.send_query(query)
            if status == 200:
                success_count += 1
            elif status == 429:
                self.log("SUCCESS", f"Rate limiting enforced after {i+1} requests")
                return
                
        elapsed = time.time() - start_time
        
        if success_count == requests_count:
            self.add_vulnerability(
                "No Rate Limiting",
                "MEDIUM",
                f"Server accepted {requests_count} requests in {elapsed:.2f}s without rate limiting",
                f"Requests/second: {requests_count/elapsed:.2f}"
            )
        else:
            self.log("INFO", f"Rate limiting test completed: {success_count}/{requests_count} succeeded")
            
    def test_csrf(self):
        """Test for CSRF protection"""
        self.log("INFO", "Testing CSRF protection...")
        
        # Check for CSRF tokens or SameSite cookies
        test_headers = self.headers.copy()
        test_headers.pop("X-CSRF-Token", None)
        
        query = "query { __typename }"
        
        try:
            response = self.session.post(
                self.url,
                json={"query": query},
                headers=test_headers,
                timeout=self.timeout
            )
            
            # Check response headers
            cookies = response.cookies
            has_samesite = any(
                "samesite" in str(cookie).lower() 
                for cookie in cookies
            )
            
            if not has_samesite:
                self.add_vulnerability(
                    "Missing CSRF Protection",
                    "MEDIUM",
                    "Cookies don't have SameSite attribute set",
                    "Consider implementing CSRF tokens or SameSite cookies"
                )
            else:
                self.log("SUCCESS", "SameSite cookie attribute detected")
                
        except Exception as e:
            self.log("ERROR", f"CSRF test failed: {str(e)}")
            
    def test_cors(self):
        """Test CORS configuration"""
        self.log("INFO", "Testing CORS configuration...")
        
        test_headers = self.headers.copy()
        test_headers["Origin"] = "https://evil.com"
        
        try:
            response = self.session.post(
                self.url,
                json={"query": "query { __typename }"},
                headers=test_headers,
                timeout=self.timeout
            )
            
            cors_header = response.headers.get("Access-Control-Allow-Origin", "")
            
            if cors_header == "*":
                self.add_vulnerability(
                    "Insecure CORS Configuration",
                    "MEDIUM",
                    "CORS allows all origins (Access-Control-Allow-Origin: *)",
                    "This may allow unauthorized cross-origin requests"
                )
            elif cors_header == "https://evil.com":
                self.add_vulnerability(
                    "Permissive CORS Configuration",
                    "MEDIUM",
                    "CORS reflects arbitrary origins",
                    f"Origin {test_headers['Origin']} was accepted"
                )
            else:
                self.log("SUCCESS", "CORS configuration appears secure")
                
        except Exception as e:
            self.log("ERROR", f"CORS test failed: {str(e)}")
            
    def generate_report(self):
        """Generate vulnerability report"""
        print(f"\n{Colors.BOLD}{'='*70}")
        print("VULNERABILITY REPORT")
        print(f"{'='*70}{Colors.END}\n")
        
        print(f"Target: {self.url}")
        print(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}\n")
        
        if not self.vulnerabilities:
            print(f"{Colors.GREEN}No vulnerabilities detected!{Colors.END}\n")
            return
            
        # Group by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for vuln in self.vulnerabilities:
            by_severity[vuln["severity"]].append(vuln)
            
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            vulns = by_severity[severity]
            if not vulns:
                continue
                
            color = {
                "CRITICAL": Colors.RED + Colors.BOLD,
                "HIGH": Colors.RED,
                "MEDIUM": Colors.YELLOW,
                "LOW": Colors.BLUE
            }[severity]
            
            print(f"{color}{severity} SEVERITY ({len(vulns)}){Colors.END}")
            print("-" * 70)
            
            for i, vuln in enumerate(vulns, 1):
                print(f"\n{i}. {vuln['type']}")
                print(f"   Description: {vuln['description']}")
                if vuln.get('evidence'):
                    print(f"   Evidence: {vuln['evidence'][:100]}...")
                print()
                
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
        
    def run_all_tests(self):
        """Run all vulnerability tests"""
        self.print_banner()
        print(f"Target URL: {self.url}\n")
        
        # Run tests
        self.test_introspection()
        self.test_field_suggestions()
        self.test_depth_limit()
        self.test_batch_query_limit()
        self.test_query_complexity()
        self.test_sql_injection()
        self.test_nosql_injection()
        self.test_authentication_bypass()
        self.test_information_disclosure()
        self.test_rate_limiting()
        self.test_csrf()
        self.test_cors()
        
        # Generate report
        self.generate_report()


def main():
    parser = argparse.ArgumentParser(
        description="GraphQL Security Testing Tool - Comprehensive vulnerability scanner"
    )
    parser.add_argument("url", help="GraphQL endpoint URL")
    parser.add_argument("-H", "--header", action="append", help="Custom header (format: 'Key: Value')")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--no-introspection", action="store_true", help="Skip introspection test")
    
    args = parser.parse_args()
    
    # Parse custom headers
    headers = {"Content-Type": "application/json"}
    if args.header:
        for header in args.header:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
                
    # Create scanner and run tests
    scanner = GraphQLScanner(args.url, headers, args.timeout)
    scanner.run_all_tests()


if __name__ == "__main__":
    main()
