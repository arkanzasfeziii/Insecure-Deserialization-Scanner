#!/usr/bin/env python3
"""
Insecure Deserialization Scanner v2.0.0
Advanced Automated Vulnerability Detection Tool
Detects insecure deserialization vulnerabilities across multiple languages:
- Python (Pickle, YAML, JSON)
- Java (Serializable objects, Gadget chains)
- PHP (unserialize)
- .NET (BinaryFormatter, XmlSerializer, Json.NET)
- Ruby (Marshal.load)
- Node.js (JSON.parse, prototype pollution)
- XML, Protobuf, Thrift, Avro

Author: Security Research Team
License: MIT (For Authorized Security Testing Only)
"""

import sys
import os
import re
import json
import base64
import pickle
import hashlib
import argparse
import logging
import subprocess
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any, Set
from urllib.parse import urlparse, urljoin
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')

# Try to import optional dependencies
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("⚠️  Warning: 'requests' not installed. HTTP scanning disabled.")
    print("   Install with: pip install requests")

try:
    from termcolor import colored, cprint
    HAS_TERMCOLOR = True
except ImportError:
    HAS_TERMCOLOR = False
    # Fallback colored function
    def colored(text, color=None, on_color=None, attrs=None):
        return text
    def cprint(text, color=None, on_color=None, attrs=None, **kwargs):
        print(text, **kwargs)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

VERSION = "2.0.0"

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          Insecure Deserialization Scanner v{}                    ║
║       Advanced Vulnerability Detection Framework                 ║
║                                                                  ║
║        Detecting Unsafe Deserialization Patterns                 ║
║                   arkanzasfeziii                                 ║
╚══════════════════════════════════════════════════════════════════╝
""".format(VERSION)

# Severity levels
SEVERITY = {
    'CRITICAL': '🔴 CRITICAL',
    'HIGH': '🟠 HIGH',
    'MEDIUM': '🟡 MEDIUM',
    'LOW': '🟢 LOW',
    'INFO': 'ℹ️  INFO'
}

# CWE References
CWE_REFERENCES = {
    'pickle': 'CWE-502: Deserialization of Untrusted Data',
    'yaml': 'CWE-502: Deserialization of Untrusted Data',
    'java': 'CWE-502: Deserialization of Untrusted Data',
    'php': 'CWE-502: Deserialization of Untrusted Data',
    'dotnet': 'CWE-502: Deserialization of Untrusted Data',
    'ruby': 'CWE-502: Deserialization of Untrusted Data',
    'nodejs': 'CWE-1321: Improperly Controlled Modification of Object Prototype'
}

# ============================================================================
# PATTERN DATABASES FOR STATIC ANALYSIS
# ============================================================================

class VulnerabilityPatterns:
    """Database of insecure deserialization patterns for all languages"""
    
    # Python patterns
    PYTHON_PATTERNS = {
        'pickle_loads': {
            'pattern': r'pickle\.loads?\s*\(',
            'severity': 'CRITICAL',
            'description': 'Unsafe pickle deserialization detected',
            'vulnerable_code': 'pickle.loads(untrusted_data)',
            'fix': 'Avoid pickle for untrusted data. Use JSON or implement whitelist validation.'
        },
        'pickle_load': {
            'pattern': r'pickle\.load\s*\(',
            'severity': 'CRITICAL',
            'description': 'Unsafe pickle deserialization from file',
            'vulnerable_code': 'pickle.load(file)',
            'fix': 'Validate file source and use safe serialization formats.'
        },
        'yaml_unsafe': {
            'pattern': r'yaml\.(unsafe_)?load\s*\(',
            'severity': 'CRITICAL',
            'description': 'Unsafe YAML deserialization (use safe_load)',
            'vulnerable_code': 'yaml.load(data)',
            'fix': 'Use yaml.safe_load() instead of yaml.load()'
        },
        'yaml_full_loader': {
            'pattern': r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.FullLoader',
            'severity': 'HIGH',
            'description': 'YAML FullLoader can execute arbitrary code',
            'vulnerable_code': 'yaml.load(data, Loader=yaml.FullLoader)',
            'fix': 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)'
        },
        'marshal_loads': {
            'pattern': r'marshal\.loads?\s*\(',
            'severity': 'HIGH',
            'description': 'Marshal deserialization from untrusted source',
            'vulnerable_code': 'marshal.loads(data)',
            'fix': 'Only use marshal for trusted, internal data. Prefer JSON.'
        },
        'shelve_open': {
            'pattern': r'shelve\.open\s*\(',
            'severity': 'MEDIUM',
            'description': 'Shelve uses pickle internally - unsafe for untrusted data',
            'vulnerable_code': 'shelve.open(untrusted_file)',
            'fix': 'Validate file source or use SQLite instead.'
        },
        'jsonpickle': {
            'pattern': r'jsonpickle\.decode\s*\(',
            'severity': 'HIGH',
            'description': 'jsonpickle can deserialize arbitrary objects',
            'vulnerable_code': 'jsonpickle.decode(untrusted_json)',
            'fix': 'Use standard json.loads() or implement type checking.'
        },
        'dill_loads': {
            'pattern': r'dill\.loads?\s*\(',
            'severity': 'CRITICAL',
            'description': 'Dill is like pickle and equally dangerous',
            'vulnerable_code': 'dill.loads(data)',
            'fix': 'Avoid dill for untrusted data. Use safe serialization.'
        }
    }
    
    # Java patterns
    JAVA_PATTERNS = {
        'objectinputstream': {
            'pattern': r'ObjectInputStream\s*\([^)]*\)\.readObject\s*\(',
            'severity': 'CRITICAL',
            'description': 'Unsafe Java deserialization - gadget chain attack vector',
            'vulnerable_code': 'new ObjectInputStream(input).readObject()',
            'fix': 'Implement ObjectInputFilter, use JSON, or whitelist allowed classes.'
        },
        'xmldecoder': {
            'pattern': r'XMLDecoder\s*\(',
            'severity': 'CRITICAL',
            'description': 'XMLDecoder can execute arbitrary code',
            'vulnerable_code': 'new XMLDecoder(inputStream).readObject()',
            'fix': 'Use safer XML parsing libraries or JSON.'
        },
        'xstream': {
            'pattern': r'XStream\s*\([^)]*\)\.fromXML\s*\(',
            'severity': 'HIGH',
            'description': 'XStream deserialization without security setup',
            'vulnerable_code': 'xstream.fromXML(xml)',
            'fix': 'Configure XStream security framework or use safe parsers.'
        },
        'snakeyaml': {
            'pattern': r'new\s+Yaml\s*\([^)]*\)\.load\s*\(',
            'severity': 'HIGH',
            'description': 'SnakeYAML unsafe deserialization',
            'vulnerable_code': 'new Yaml().load(input)',
            'fix': 'Use Yaml with SafeConstructor or JSON instead.'
        },
        'commons_collections': {
            'pattern': r'import\s+org\.apache\.commons\.collections',
            'severity': 'HIGH',
            'description': 'Commons Collections gadget chain vulnerability',
            'vulnerable_code': 'Using vulnerable Commons Collections version',
            'fix': 'Update to Commons Collections 3.2.2+ or remove dependency.'
        },
        'fastjson': {
            'pattern': r'JSON\.parse(Object)?\s*\(',
            'severity': 'CRITICAL',
            'description': 'Fastjson AutoType deserialization vulnerability',
            'vulnerable_code': 'JSON.parseObject(json)',
            'fix': 'Disable AutoType: ParserConfig.getGlobalInstance().setAutoTypeSupport(false)'
        },
        'jackson_polymorphic': {
            'pattern': r'@JsonTypeInfo\s*\([^)]*use\s*=\s*JsonTypeInfo\.Id\.CLASS',
            'severity': 'HIGH',
            'description': 'Jackson polymorphic deserialization with CLASS typing',
            'vulnerable_code': '@JsonTypeInfo(use = Id.CLASS)',
            'fix': 'Use @JsonTypeInfo(use = Id.NAME) with whitelist.'
        }
    }
    
    # PHP patterns
    PHP_PATTERNS = {
        'unserialize': {
            'pattern': r'unserialize\s*\(\s*\$',
            'severity': 'CRITICAL',
            'description': 'PHP unserialize() on untrusted data - object injection',
            'vulnerable_code': 'unserialize($_POST["data"])',
            'fix': 'Use json_decode() or implement allowed_classes whitelist.'
        },
        'unserialize_callback': {
            'pattern': r'unserialize_callback_func',
            'severity': 'HIGH',
            'description': 'Custom unserialize callback can be exploited',
            'vulnerable_code': 'ini_set("unserialize_callback_func", ...)',
            'fix': 'Avoid custom callbacks or strictly validate input.'
        },
        'phar_deserialization': {
            'pattern': r'(file_get_contents|fopen|file_exists|stat)\s*\(\s*["\']phar://',
            'severity': 'HIGH',
            'description': 'PHAR deserialization vulnerability',
            'vulnerable_code': 'file_get_contents("phar://...")',
            'fix': 'Validate file paths and disable phar:// wrapper if not needed.'
        },
        'magic_method_wakeup': {
            'pattern': r'function\s+__wakeup\s*\(',
            'severity': 'MEDIUM',
            'description': '__wakeup magic method - potential gadget chain',
            'vulnerable_code': 'function __wakeup() { ... }',
            'fix': 'Review __wakeup logic for dangerous operations.'
        },
        'magic_method_destruct': {
            'pattern': r'function\s+__destruct\s*\(',
            'severity': 'MEDIUM',
            'description': '__destruct magic method - potential gadget chain',
            'vulnerable_code': 'function __destruct() { ... }',
            'fix': 'Ensure __destruct cannot trigger harmful actions.'
        }
    }
    
    # .NET patterns
    DOTNET_PATTERNS = {
        'binaryformatter': {
            'pattern': r'BinaryFormatter\s*\([^)]*\)\.Deserialize\s*\(',
            'severity': 'CRITICAL',
            'description': 'BinaryFormatter deserialization - extremely dangerous',
            'vulnerable_code': 'new BinaryFormatter().Deserialize(stream)',
            'fix': 'Never use BinaryFormatter. Migrate to JSON or implement SerializationBinder.'
        },
        'netdatacontractserializer': {
            'pattern': r'NetDataContractSerializer\s*\([^)]*\)\.Deserialize',
            'severity': 'CRITICAL',
            'description': 'NetDataContractSerializer unsafe deserialization',
            'vulnerable_code': 'new NetDataContractSerializer().Deserialize(stream)',
            'fix': 'Use DataContractSerializer with known types only.'
        },
        'losformatter': {
            'pattern': r'LosFormatter\s*\([^)]*\)\.Deserialize\s*\(',
            'severity': 'CRITICAL',
            'description': 'LosFormatter deserialization vulnerability',
            'vulnerable_code': 'new LosFormatter().Deserialize(data)',
            'fix': 'Avoid LosFormatter. Use secure JSON serialization.'
        },
        'objectstateformatter': {
            'pattern': r'ObjectStateFormatter\s*\([^)]*\)\.Deserialize\s*\(',
            'severity': 'CRITICAL',
            'description': 'ObjectStateFormatter unsafe deserialization',
            'vulnerable_code': 'new ObjectStateFormatter().Deserialize(data)',
            'fix': 'Replace with JSON or implement strict type filtering.'
        },
        'jsonnet_typenamehandling': {
            'pattern': r'TypeNameHandling\s*=\s*TypeNameHandling\.(All|Objects|Auto)',
            'severity': 'CRITICAL',
            'description': 'Json.NET with TypeNameHandling enabled',
            'vulnerable_code': 'TypeNameHandling = TypeNameHandling.All',
            'fix': 'Set TypeNameHandling = TypeNameHandling.None'
        },
        'xmlserializer_unsafe': {
            'pattern': r'XmlSerializer\s*\([^)]*\)\.Deserialize\s*\(',
            'severity': 'MEDIUM',
            'description': 'XmlSerializer with untrusted input',
            'vulnerable_code': 'new XmlSerializer(type).Deserialize(reader)',
            'fix': 'Validate XML input and restrict allowed types.'
        }
    }
    
    # Ruby patterns
    RUBY_PATTERNS = {
        'marshal_load': {
            'pattern': r'Marshal\.(load|restore)\s*\(',
            'severity': 'CRITICAL',
            'description': 'Ruby Marshal deserialization - code execution risk',
            'vulnerable_code': 'Marshal.load(untrusted_data)',
            'fix': 'Use JSON or YAML.safe_load instead.'
        },
        'yaml_load': {
            'pattern': r'YAML\.(load|load_file)\s*\(',
            'severity': 'HIGH',
            'description': 'Ruby YAML.load is unsafe - use safe_load',
            'vulnerable_code': 'YAML.load(data)',
            'fix': 'Use YAML.safe_load(data, permitted_classes: [...])'
        },
        'oj_load': {
            'pattern': r'Oj\.(load|object_load)\s*\(',
            'severity': 'MEDIUM',
            'description': 'Oj gem object deserialization',
            'vulnerable_code': 'Oj.load(json, mode: :object)',
            'fix': 'Use Oj.load with mode: :strict or :compat'
        }
    }
    
    # Node.js/JavaScript patterns
    NODEJS_PATTERNS = {
        'eval_json': {
            'pattern': r'eval\s*\(\s*[\'"]?\s*\(?.*?JSON',
            'severity': 'CRITICAL',
            'description': 'Using eval() for JSON parsing',
            'vulnerable_code': 'eval("(" + json + ")")',
            'fix': 'Always use JSON.parse() instead of eval().'
        },
        'function_constructor': {
            'pattern': r'new\s+Function\s*\(',
            'severity': 'HIGH',
            'description': 'Function constructor with untrusted input',
            'vulnerable_code': 'new Function(untrustedCode)()',
            'fix': 'Avoid dynamic code execution. Use safer alternatives.'
        },
        'vm_runin': {
            'pattern': r'vm\.runIn(This|New)Context\s*\(',
            'severity': 'HIGH',
            'description': 'Node.js vm module can be escaped',
            'vulnerable_code': 'vm.runInNewContext(code)',
            'fix': 'Use vm2 library or avoid dynamic code execution.'
        },
        'prototype_pollution': {
            'pattern': r'(Object\.assign|\.\.\.)\s*\(\s*\{\s*\}\s*,\s*[a-zA-Z_$]',
            'severity': 'MEDIUM',
            'description': 'Potential prototype pollution vulnerability',
            'vulnerable_code': 'Object.assign({}, userInput)',
            'fix': 'Validate object keys and use Object.create(null).'
        },
        'node_serialize': {
            'pattern': r'require\s*\(\s*[\'"]node-serialize[\'"]\s*\)',
            'severity': 'CRITICAL',
            'description': 'node-serialize has known deserialization vulnerability',
            'vulnerable_code': 'serialize.unserialize(data)',
            'fix': 'Replace node-serialize with JSON or safer alternatives.'
        },
        'funcster': {
            'pattern': r'require\s*\(\s*[\'"]funcster[\'"]\s*\)',
            'severity': 'HIGH',
            'description': 'funcster deserializes functions - dangerous',
            'vulnerable_code': 'funcster.deserialize(data)',
            'fix': 'Avoid deserializing functions. Use JSON.'
        }
    }
    
    # XML patterns
    XML_PATTERNS = {
        'xxe_vulnerability': {
            'pattern': r'(DocumentBuilder|SAXParser|XMLReader).*\.parse\s*\(',
            'severity': 'HIGH',
            'description': 'XML parser without XXE protection',
            'vulnerable_code': 'DocumentBuilder.parse(xmlInput)',
            'fix': 'Disable external entities: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)'
        },
        'xstream_security': {
            'pattern': r'XStream.*setupDefaultSecurity',
            'severity': 'MEDIUM',
            'description': 'XStream security configuration check',
            'vulnerable_code': 'Check if security is properly configured',
            'fix': 'Call xstream.setupDefaultSecurity()'
        }
    }
    
    @classmethod
    def get_all_patterns(cls) -> Dict[str, Dict]:
        """Get all vulnerability patterns"""
        return {
            'python': cls.PYTHON_PATTERNS,
            'java': cls.JAVA_PATTERNS,
            'php': cls.PHP_PATTERNS,
            'dotnet': cls.DOTNET_PATTERNS,
            'ruby': cls.RUBY_PATTERNS,
            'nodejs': cls.NODEJS_PATTERNS,
            'xml': cls.XML_PATTERNS
        }

# ============================================================================
# PAYLOAD GENERATORS FOR DYNAMIC TESTING
# ============================================================================

class PayloadGenerator:
    """Generate safe test payloads for dynamic analysis"""
    
    @staticmethod
    def generate_python_pickle_payload() -> bytes:
        """Generate safe Python pickle payload for testing"""
        # Safe test payload that doesn't execute harmful code
        class SafeTestObject:
            def __init__(self):
                self.test_marker = "DESERIAL_TEST_MARKER_" + hashlib.md5(b"test").hexdigest()
                self.timestamp = datetime.now().isoformat()
        
        try:
            obj = SafeTestObject()
            return pickle.dumps(obj)
        except Exception as e:
            logging.error(f"Error generating pickle payload: {e}")
            return b''
    
    @staticmethod
    def generate_yaml_payload() -> str:
        """Generate YAML payload for testing"""
        return """!!python/object/apply:os.system
args: ['echo DESERIAL_TEST_MARKER']
"""
    
    @staticmethod
    def generate_java_payload() -> str:
        """Generate Java serialized object base64"""
        # This is a safe marker payload, not actual exploitation
        java_serial_marker = "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=="
        return java_serial_marker
    
    @staticmethod
    def generate_php_payload() -> str:
        """Generate PHP serialized object"""
        # Safe test object
        return 'O:8:"stdClass":1:{s:11:"test_marker";s:32:"DESERIAL_TEST_MARKER_PHP";}'
    
    @staticmethod
    def generate_dotnet_payload() -> str:
        """Generate .NET BinaryFormatter payload marker"""
        # Safe marker for detection
        return "AAEAAAD/////AQAAAAAAAAAEAQAAAA=="
    
    @staticmethod
    def generate_ruby_marshal_payload() -> bytes:
        """Generate Ruby Marshal payload"""
        # Safe test marker
        return b"\x04\x08o:\x0bObject\x00"
    
    @staticmethod
    def generate_nodejs_payload() -> str:
        """Generate Node.js prototype pollution test"""
        return '{"__proto__": {"test_marker": "DESERIAL_TEST"}}'

# ============================================================================
# STATIC CODE ANALYZER
# ============================================================================

class StaticAnalyzer:
    """Analyzes source code for insecure deserialization patterns"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.patterns = VulnerabilityPatterns.get_all_patterns()
        self.findings = []
    
    def analyze_file(self, file_path: str) -> List[Dict]:
        """Analyze a single source file"""
        findings = []
        
        try:
            if not os.path.exists(file_path):
                logging.error(f"File not found: {file_path}")
                return findings
            
            if not os.path.isfile(file_path):
                logging.warning(f"Not a file: {file_path}")
                return findings
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Detect language
            language = self._detect_language(file_path, content)
            
            if language == 'unknown' or language not in self.patterns:
                if self.verbose:
                    logging.info(f"Unsupported language for {file_path}")
                return findings
            
            # Scan for patterns
            patterns = self.patterns[language]
            
            for pattern_name, pattern_info in patterns.items():
                try:
                    matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE | re.IGNORECASE)
                    
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        line_content = lines[line_num - 1].strip() if 0 <= line_num - 1 < len(lines) else ""
                        
                        finding = {
                            'type': 'insecure_deserialization',
                            'file': file_path,
                            'line': line_num,
                            'pattern': pattern_name,
                            'severity': pattern_info['severity'],
                            'description': pattern_info['description'],
                            'vulnerable_code': line_content,
                            'fix': pattern_info['fix'],
                            'cwe': CWE_REFERENCES.get(language, 'CWE-502'),
                            'language': language
                        }
                        
                        findings.append(finding)
                        self.findings.append(finding)
                except Exception as e:
                    logging.error(f"Error processing pattern {pattern_name}: {e}")
                    continue
            
            return findings
            
        except Exception as e:
            logging.error(f"Error analyzing {file_path}: {str(e)}")
            return findings
    
    def analyze_directory(self, directory: str) -> List[Dict]:
        """Recursively analyze all files in directory"""
        all_findings = []
        
        try:
            if not os.path.exists(directory):
                logging.error(f"Directory not found: {directory}")
                return all_findings
            
            if not os.path.isdir(directory):
                logging.error(f"Not a directory: {directory}")
                return all_findings
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        findings = self.analyze_file(file_path)
                        all_findings.extend(findings)
                    except Exception as e:
                        logging.error(f"Error analyzing file {file_path}: {e}")
                        continue
        except Exception as e:
            logging.error(f"Error analyzing directory {directory}: {e}")
        
        return all_findings
    
    def _detect_language(self, file_path: str, content: str) -> str:
        """Detect programming language from file"""
        try:
            ext = Path(file_path).suffix.lower()
            
            extension_map = {
                '.py': 'python',
                '.java': 'java',
                '.php': 'php',
                '.cs': 'dotnet',
                '.vb': 'dotnet',
                '.rb': 'ruby',
                '.js': 'nodejs',
                '.ts': 'nodejs',
                '.xml': 'xml'
            }
            
            if ext in extension_map:
                return extension_map[ext]
            
            # Content-based detection
            if 'import pickle' in content or 'import yaml' in content:
                return 'python'
            elif 'ObjectInputStream' in content or 'import java.' in content:
                return 'java'
            elif 'unserialize' in content or '<?php' in content:
                return 'php'
            elif 'BinaryFormatter' in content or 'using System' in content:
                return 'dotnet'
            elif 'Marshal.load' in content or 'require ' in content:
                return 'ruby'
            elif 'require(' in content or 'JSON.parse' in content:
                return 'nodejs'
            
            return 'unknown'
        except Exception as e:
            logging.error(f"Error detecting language: {e}")
            return 'unknown'

# ============================================================================
# DYNAMIC VULNERABILITY TESTER
# ============================================================================

class DynamicTester:
    """Dynamic testing for web applications and APIs"""
    
    def __init__(self, timeout: int = 10, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.findings = []
        self.session = self._create_session() if HAS_REQUESTS else None
    
    def _create_session(self):
        """Create HTTP session with retry logic"""
        try:
            session = requests.Session()
            retry = Retry(total=3, backoff_factor=0.3)
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            return session
        except Exception as e:
            logging.error(f"Error creating session: {e}")
            return None
    
    def test_url(self, url: str, method: str = 'POST') -> List[Dict]:
        """Test URL for deserialization vulnerabilities"""
        if not HAS_REQUESTS:
            logging.error("requests library not installed. Cannot perform dynamic testing.")
            return []
        
        if not self.session:
            logging.error("Failed to create HTTP session")
            return []
        
        findings = []
        payloads = self._generate_test_payloads()
        
        for payload_info in payloads:
            try:
                if self.verbose:
                    print(f"  Testing {payload_info['name']}...")
                
                # Test with different content types
                for content_type in payload_info['content_types']:
                    try:
                        headers = {'Content-Type': content_type}
                        
                        if method.upper() == 'POST':
                            response = self.session.post(
                                url, 
                                data=payload_info['payload'],
                                headers=headers, 
                                timeout=self.timeout,
                                verify=False, 
                                allow_redirects=False
                            )
                        else:
                            response = self.session.get(
                                url, 
                                params={'data': payload_info['payload']},
                                headers=headers, 
                                timeout=self.timeout,
                                verify=False, 
                                allow_redirects=False
                            )
                        
                        # Analyze response
                        vulnerability = self._analyze_response(response, payload_info, url)
                        if vulnerability:
                            findings.append(vulnerability)
                            self.findings.append(vulnerability)
                    except requests.exceptions.Timeout:
                        if self.verbose:
                            print(f"  ⚠️  Timeout testing {payload_info['name']}")
                    except requests.exceptions.RequestException as e:
                        if self.verbose:
                            logging.debug(f"Request error testing {payload_info['name']}: {str(e)}")
                    except Exception as e:
                        if self.verbose:
                            logging.debug(f"Error testing {payload_info['name']}: {str(e)}")
                
            except Exception as e:
                logging.error(f"Error in payload loop: {e}")
                continue
        
        return findings
    
    def _generate_test_payloads(self) -> List[Dict]:
        """Generate all test payloads"""
        generator = PayloadGenerator()
        payloads = []
        
        # Python Pickle
        try:
            pickle_payload = generator.generate_python_pickle_payload()
            if pickle_payload:
                payloads.append({
                    'name': 'Python Pickle',
                    'payload': base64.b64encode(pickle_payload).decode(),
                    'content_types': ['application/octet-stream', 'application/x-pickle'],
                    'language': 'python',
                    'severity': 'CRITICAL'
                })
        except Exception as e:
            logging.error(f"Error generating pickle payload: {e}")
        
        # Add other payloads with error handling
        try:
            payloads.extend([
                {
                    'name': 'Java Serialized',
                    'payload': generator.generate_java_payload(),
                    'content_types': ['application/x-java-serialized-object', 'application/octet-stream'],
                    'language': 'java',
                    'severity': 'CRITICAL'
                },
                {
                    'name': 'PHP Serialized',
                    'payload': generator.generate_php_payload(),
                    'content_types': ['application/x-php-serialized', 'text/plain'],
                    'language': 'php',
                    'severity': 'CRITICAL'
                },
                {
                    'name': '.NET BinaryFormatter',
                    'payload': generator.generate_dotnet_payload(),
                    'content_types': ['application/octet-stream', 'application/x-dotnet-serialized'],
                    'language': 'dotnet',
                    'severity': 'CRITICAL'
                },
                {
                    'name': 'YAML Unsafe',
                    'payload': generator.generate_yaml_payload(),
                    'content_types': ['application/x-yaml', 'text/yaml'],
                    'language': 'python',
                    'severity': 'CRITICAL'
                },
                {
                    'name': 'Node.js Prototype Pollution',
                    'payload': generator.generate_nodejs_payload(),
                    'content_types': ['application/json'],
                    'language': 'nodejs',
                    'severity': 'HIGH'
                }
            ])
        except Exception as e:
            logging.error(f"Error adding payloads: {e}")
        
        return payloads
    
    def _analyze_response(self, response, payload_info: Dict, url: str) -> Optional[Dict]:
        """Analyze HTTP response for vulnerability indicators"""
        try:
            if not response:
                return None
            
            indicators = [
                'DESERIAL_TEST_MARKER',
                'unserialization',
                'deserialization',
                'ClassNotFoundException',
                'UnpicklingError',
                'YAML::ConstantNode',
                'ObjectInputStream',
                'unserialize(): Error',
                'pickle',
                'marshal'
            ]
            
            response_text = ""
            try:
                response_text = response.text.lower() if hasattr(response, 'text') and response.text else ""
            except Exception:
                response_text = ""
            
            for indicator in indicators:
                if indicator.lower() in response_text:
                    return {
                        'type': 'insecure_deserialization',
                        'url': url,
                        'method': payload_info.get('name', 'unknown'),
                        'severity': payload_info.get('severity', 'MEDIUM'),
                        'description': f'Potential deserialization vulnerability detected ({payload_info.get("language", "unknown")})',
                        'evidence': f'Response contains indicator: {indicator}',
                        'fix': self._get_fix_recommendation(payload_info.get('language', 'unknown')),
                        'cwe': CWE_REFERENCES.get(payload_info.get('language', 'unknown'), 'CWE-502')
                    }
            
            # Check for error responses that might indicate deserialization attempt
            if hasattr(response, 'status_code') and response.status_code >= 500:
                return {
                    'type': 'possible_deserialization',
                    'url': url,
                    'method': payload_info.get('name', 'unknown'),
                    'severity': 'MEDIUM',
                    'description': f'Server error when testing {payload_info.get("language", "unknown")} deserialization',
                    'evidence': f'HTTP {response.status_code} error received',
                    'fix': 'Review server logs for deserialization errors',
                    'cwe': CWE_REFERENCES.get(payload_info.get('language', 'unknown'), 'CWE-502')
                }
            
            return None
        except Exception as e:
            logging.error(f"Error analyzing response: {e}")
            return None
    
    def _get_fix_recommendation(self, language: str) -> str:
        """Get fix recommendation for specific language"""
        fixes = {
            'python': 'Use JSON instead of pickle. If YAML needed, use yaml.safe_load().',
            'java': 'Implement ObjectInputFilter or use JSON serialization.',
            'php': 'Replace unserialize() with json_decode() or use allowed_classes option.',
            'dotnet': 'Avoid BinaryFormatter. Use JSON or DataContractSerializer with known types.',
            'ruby': 'Use JSON or YAML.safe_load instead of Marshal.load.',
            'nodejs': 'Validate JSON keys and use Object.create(null) to prevent prototype pollution.'
        }
        return fixes.get(language, 'Use safe serialization formats like JSON.')

# ============================================================================
# SERIALIZED FILE ANALYZER
# ============================================================================

class SerializedFileAnalyzer:
    """Analyze serialized files for vulnerabilities"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings = []
    
    def analyze_file(self, file_path: str) -> List[Dict]:
        """Analyze a serialized file"""
        findings = []
        
        try:
            if not os.path.exists(file_path):
                logging.error(f"File not found: {file_path}")
                return findings
            
            if not os.path.isfile(file_path):
                logging.error(f"Not a file: {file_path}")
                return findings
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                logging.warning(f"Empty file: {file_path}")
                return findings
            
            # Detect format
            file_format = self._detect_format(data, file_path)
            
            if file_format == 'pickle':
                findings.extend(self._analyze_pickle(file_path, data))
            elif file_format == 'java':
                findings.extend(self._analyze_java(file_path, data))
            elif file_format == 'php':
                findings.extend(self._analyze_php(file_path, data))
            elif file_format == 'dotnet':
                findings.extend(self._analyze_dotnet(file_path, data))
            elif file_format == 'yaml':
                findings.extend(self._analyze_yaml(file_path, data))
            else:
                if self.verbose:
                    logging.info(f"Unknown serialization format: {file_path}")
            
            self.findings.extend(findings)
            return findings
            
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")
            return findings
    
    def _detect_format(self, data: bytes, file_path: str) -> str:
        """Detect serialization format"""
        try:
            if not data or len(data) < 2:
                return 'unknown'
            
            # Magic bytes detection
            if data.startswith(b'\x80\x03') or data.startswith(b'\x80\x04') or data.startswith(b'\x80\x02'):
                return 'pickle'
            elif data.startswith(b'\xac\xed\x00\x05'):
                return 'java'
            elif data.startswith(b'O:') or data.startswith(b'a:'):
                return 'php'
            
            if len(data) >= 100 and b'<?xml' in data[:100]:
                return 'xml'
            
            # Extension-based detection
            ext = Path(file_path).suffix.lower()
            if ext in ['.pkl', '.pickle']:
                return 'pickle'
            elif ext in ['.ser', '.serialized']:
                return 'java'
            elif ext in ['.yaml', '.yml']:
                return 'yaml'
            
            return 'unknown'
        except Exception as e:
            logging.error(f"Error detecting format: {e}")
            return 'unknown'
    
    def _analyze_pickle(self, file_path: str, data: bytes) -> List[Dict]:
        """Analyze pickle file"""
        findings = []
        
        try:
            # Check for dangerous opcodes
            dangerous_opcodes = [
                b'c__builtin__\neval',
                b'c__builtin__\nexec',
                b'cos\nsystem',
                b'csubprocess\ncall',
                b'csubprocess\nPopen',
                b'c__builtin__\n__import__'
            ]
            
            for opcode in dangerous_opcodes:
                if opcode in data:
                    findings.append({
                        'type': 'insecure_deserialization',
                        'file': file_path,
                        'severity': 'CRITICAL',
                        'description': 'Pickle file contains dangerous opcode',
                        'evidence': f'Found dangerous opcode: {opcode.decode("utf-8", errors="ignore")}',
                        'fix': 'Do not unpickle untrusted files. Use JSON instead.',
                        'cwe': 'CWE-502',
                        'language': 'python'
                    })
            
            # Check for GLOBAL/INST opcodes
            try:
                data_upper = data.upper()
                if b'GLOBAL' in data_upper or b'INST' in data_upper:
                    findings.append({
                        'type': 'insecure_deserialization',
                        'file': file_path,
                        'severity': 'HIGH',
                        'description': 'Pickle file contains object instantiation',
                        'evidence': 'File uses GLOBAL or INST opcodes',
                        'fix': 'Validate pickle source and implement whitelist.',
                        'cwe': 'CWE-502',
                        'language': 'python'
                    })
            except Exception:
                pass
        except Exception as e:
            logging.error(f"Error analyzing pickle: {e}")
        
        return findings
    
    def _analyze_java(self, file_path: str, data: bytes) -> List[Dict]:
        """Analyze Java serialized object"""
        findings = []
        
        try:
            # Check for known gadget chain classes
            gadget_classes = [
                b'org.apache.commons.collections',
                b'org.springframework.beans',
                b'com.sun.rowset.JdbcRowSetImpl',
                b'org.jboss.interceptor',
                b'com.sun.org.apache.xalan'
            ]
            
            for gadget in gadget_classes:
                if gadget in data:
                    findings.append({
                        'type': 'insecure_deserialization',
                        'file': file_path,
                        'severity': 'CRITICAL',
                        'description': 'Java serialized object contains known gadget chain class',
                        'evidence': f'Found class: {gadget.decode("utf-8")}',
                        'fix': 'Implement ObjectInputFilter to whitelist safe classes.',
                        'cwe': 'CWE-502',
                        'language': 'java'
                    })
        except Exception as e:
            logging.error(f"Error analyzing Java object: {e}")
        
        return findings
    
    def _analyze_php(self, file_path: str, data: bytes) -> List[Dict]:
        """Analyze PHP serialized data"""
        findings = []
        
        try:
            # Check for object serialization
            if b'O:' in data:
                findings.append({
                    'type': 'insecure_deserialization',
                    'file': file_path,
                    'severity': 'HIGH',
                    'description': 'PHP serialized object detected',
                    'evidence': 'File contains serialized PHP objects',
                    'fix': 'Use json_encode/decode or unserialize with allowed_classes.',
                    'cwe': 'CWE-502',
                    'language': 'php'
                })
        except Exception as e:
            logging.error(f"Error analyzing PHP data: {e}")
        
        return findings
    
    def _analyze_dotnet(self, file_path: str, data: bytes) -> List[Dict]:
        """Analyze .NET serialized data"""
        findings = []
        
        try:
            # Check for BinaryFormatter signature
            if len(data) >= 100:
                encoded = base64.b64encode(data[:100])
                if b'AAEAAAD' in encoded:
                    findings.append({
                        'type': 'insecure_deserialization',
                        'file': file_path,
                        'severity': 'CRITICAL',
                        'description': '.NET BinaryFormatter serialized data detected',
                        'evidence': 'File contains BinaryFormatter signature',
                        'fix': 'Never use BinaryFormatter. Migrate to JSON.',
                        'cwe': 'CWE-502',
                        'language': 'dotnet'
                    })
        except Exception as e:
            logging.error(f"Error analyzing .NET data: {e}")
        
        return findings
    
    def _analyze_yaml(self, file_path: str, data: bytes) -> List[Dict]:
        """Analyze YAML file for dangerous constructs"""
        findings = []
        
        try:
            content = data.decode('utf-8', errors='ignore')
            
            dangerous_tags = [
                '!!python/object/apply',
                '!!python/object/new',
                '!!python/name',
                '!!python/module'
            ]
            
            for tag in dangerous_tags:
                if tag in content:
                    findings.append({
                        'type': 'insecure_deserialization',
                        'file': file_path,
                        'severity': 'CRITICAL',
                        'description': 'YAML file contains dangerous Python object tag',
                        'evidence': f'Found tag: {tag}',
                        'fix': 'Use yaml.safe_load() instead of yaml.load().',
                        'cwe': 'CWE-502',
                        'language': 'python'
                    })
        except Exception as e:
            logging.error(f"Error analyzing YAML: {e}")
        
        return findings

# ============================================================================
# NETWORK TRAFFIC ANALYZER
# ============================================================================

class NetworkTrafficAnalyzer:
    """Analyze network traffic for serialized data"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings = []
    
    def analyze_pcap(self, pcap_file: str) -> List[Dict]:
        """Analyze PCAP file for serialization traffic"""
        findings = []
        
        try:
            if not os.path.exists(pcap_file):
                logging.error(f"PCAP file not found: {pcap_file}")
                return findings
            
            # Try to use scapy if available
            HAS_SCAPY = False
            try:
                from scapy.all import rdpcap, Raw
                HAS_SCAPY = True
            except ImportError:
                if self.verbose:
                    print("ℹ️  scapy not installed. Limited PCAP analysis.")
                    print("   Install with: pip install scapy")
            
            if HAS_SCAPY:
                try:
                    packets = rdpcap(pcap_file)
                    
                    for packet in packets:
                        try:
                            if packet.haslayer(Raw):
                                payload = bytes(packet[Raw].load)
                                
                                # Check for serialization signatures
                                if self._is_serialized_data(payload):
                                    findings.append({
                                        'type': 'insecure_deserialization',
                                        'file': pcap_file,
                                        'severity': 'HIGH',
                                        'description': 'Serialized data found in network traffic',
                                        'evidence': f'Packet contains serialized data (size: {len(payload)} bytes)',
                                        'fix': 'Encrypt and authenticate serialized data in transit.',
                                        'cwe': 'CWE-502'
                                    })
                                    break  # Only report once
                        except Exception:
                            continue
                except Exception as e:
                    logging.error(f"Scapy PCAP parsing error: {e}")
            else:
                # Fallback: simple binary analysis
                with open(pcap_file, 'rb') as f:
                    data = f.read()
                    if self._is_serialized_data(data):
                        findings.append({
                            'type': 'possible_deserialization',
                            'file': pcap_file,
                            'severity': 'MEDIUM',
                            'description': 'Possible serialized data in PCAP',
                            'evidence': 'File contains serialization signatures',
                            'fix': 'Use scapy for detailed analysis: pip install scapy',
                            'cwe': 'CWE-502'
                        })
            
            self.findings.extend(findings)
            return findings
            
        except Exception as e:
            logging.error(f"Error analyzing PCAP {pcap_file}: {str(e)}")
            return findings
    
    def _is_serialized_data(self, data: bytes) -> bool:
        """Check if data contains serialization signatures"""
        if not data or len(data) < 2:
            return False
        
        signatures = [
            b'\x80\x03',  # Pickle
            b'\xac\xed\x00\x05',  # Java
            b'O:',  # PHP
            b'AAEAAAD',  # .NET
            b'!!python'  # YAML
        ]
        
        # Check first 1KB
        check_size = min(len(data), 1000)
        data_check = data[:check_size]
        
        for sig in signatures:
            if sig in data_check:
                return True
        return False

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate comprehensive vulnerability reports"""
    
    def __init__(self, findings: List[Dict], verbose: bool = False):
        self.findings = findings
        self.verbose = verbose
    
    def generate_console_report(self, simple: bool = False):
        """Generate console report"""
        if not self.findings:
            cprint("\n✅ Great job! No insecure deserialization vulnerabilities found! 🎉\n", 'green', attrs=['bold'])
            return
        
        cprint(f"\n{'='*70}", 'red', attrs=['bold'])
        cprint("⚠️  INSECURE DESERIALIZATION VULNERABILITIES DETECTED", 'red', attrs=['bold'])
        cprint(f"{'='*70}\n", 'red', attrs=['bold'])
        
        # Group by severity
        by_severity = {}
        for finding in self.findings:
            severity = finding.get('severity', 'MEDIUM')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        
        # Display summary
        cprint(f"Total Issues Found: {len(self.findings)}", 'yellow', attrs=['bold'])
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                count = len(by_severity[severity])
                cprint(f"  {SEVERITY[severity]}: {count}", 'red' if severity == 'CRITICAL' else 'yellow')
        print()
        
        # Display each finding
        for i, finding in enumerate(self.findings, 1):
            severity = finding.get('severity', 'MEDIUM')
            severity_color = 'red' if severity == 'CRITICAL' else 'yellow' if severity in ['HIGH', 'MEDIUM'] else 'green'
            
            cprint(f"\n[{i}] {SEVERITY.get(severity, severity)} - {finding.get('description', 'Unknown')}", severity_color, attrs=['bold'])
            
            if 'file' in finding:
                print(f"    📁 File: {finding['file']}")
                if 'line' in finding:
                    print(f"    📍 Line: {finding['line']}")
            
            if 'url' in finding:
                print(f"    🌐 URL: {finding['url']}")
            
            if 'language' in finding:
                print(f"    💻 Language: {finding['language'].upper()}")
            
            if 'cwe' in finding:
                print(f"    🔍 Reference: {finding['cwe']}")
            
            if 'vulnerable_code' in finding and not simple:
                print(f"    ❌ Vulnerable Code:")
                print(f"       {finding['vulnerable_code']}")
            
            if 'evidence' in finding:
                print(f"    📋 Evidence: {finding['evidence']}")
            
            if 'fix' in finding:
                if simple:
                    cprint(f"    💡 How to fix: {finding['fix']}", 'cyan')
                else:
                    cprint(f"    ✅ Fix Recommendation:", 'green', attrs=['bold'])
                    cprint(f"       {finding['fix']}", 'cyan')
        
        cprint(f"\n{'='*70}\n", 'red', attrs=['bold'])
        
        if simple:
            cprint("😊 Don't worry! Follow the fix recommendations above to make your code safe!", 'cyan', attrs=['bold'])
        else:
            cprint("⚠️  Please address these vulnerabilities to prevent potential security breaches.", 'yellow', attrs=['bold'])
    
    def generate_json_report(self, output_file: str):
        """Generate JSON report"""
        try:
            report = {
                'scan_date': datetime.now().isoformat(),
                'total_findings': len(self.findings),
                'findings': self.findings,
                'summary': self._generate_summary()
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            
            cprint(f"\n✅ JSON report saved to: {output_file}", 'green')
        except Exception as e:
            logging.error(f"Error generating JSON report: {str(e)}")
            cprint(f"❌ Failed to save JSON report: {e}", 'red')
    
    def generate_html_report(self, output_file: str):
        """Generate HTML report"""
        try:
            html = self._build_html_report()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)
            
            cprint(f"\n✅ HTML report saved to: {output_file}", 'green')
        except Exception as e:
            logging.error(f"Error generating HTML report: {str(e)}")
            cprint(f"❌ Failed to save HTML report: {e}", 'red')
    
    def _generate_summary(self) -> Dict:
        """Generate summary statistics"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'by_language': {},
            'by_type': {}
        }
        
        for finding in self.findings:
            severity = finding.get('severity', 'MEDIUM').lower()
            if severity in summary:
                summary[severity] += 1
            
            lang = finding.get('language', 'unknown')
            summary['by_language'][lang] = summary['by_language'].get(lang, 0) + 1
            
            ftype = finding.get('type', 'unknown')
            summary['by_type'][ftype] = summary['by_type'].get(ftype, 0) + 1
        
        return summary
    
    def _build_html_report(self) -> str:
        """Build HTML report"""
        summary = self._generate_summary()
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Insecure Deserialization Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #d32f2f; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding {{ background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #ff9800; border-radius: 5px; }}
        .critical {{ border-left-color: #d32f2f; }}
        .high {{ border-left-color: #ff5722; }}
        .medium {{ border-left-color: #ff9800; }}
        .low {{ border-left-color: #4caf50; }}
        .severity {{ display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }}
        .severity-critical {{ background: #d32f2f; }}
        .severity-high {{ background: #ff5722; }}
        .severity-medium {{ background: #ff9800; }}
        .severity-low {{ background: #4caf50; }}
        .fix {{ background: #e8f5e9; padding: 10px; margin: 10px 0; border-left: 3px solid #4caf50; }}
        code {{ background: #f5f5f5; padding: 2px 5px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Insecure Deserialization Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Findings:</strong> {len(self.findings)}</p>
        <ul>
            <li>🔴 Critical: {summary['critical']}</li>
            <li>🟠 High: {summary['high']}</li>
            <li>🟡 Medium: {summary['medium']}</li>
            <li>🟢 Low: {summary['low']}</li>
        </ul>
    </div>
"""
        
        for i, finding in enumerate(self.findings, 1):
            severity = finding.get('severity', 'MEDIUM').lower()
            html += f"""
    <div class="finding {severity}">
        <h3>[{i}] <span class="severity severity-{severity}">{finding.get('severity', 'MEDIUM')}</span> {finding.get('description', 'Unknown')}</h3>
"""
            
            if 'file' in finding:
                html += f"<p><strong>📁 File:</strong> <code>{finding['file']}</code>"
                if 'line' in finding:
                    html += f" (Line {finding['line']})"
                html += "</p>"
            
            if 'url' in finding:
                html += f"<p><strong>🌐 URL:</strong> <code>{finding['url']}</code></p>"
            
            if 'language' in finding:
                html += f"<p><strong>💻 Language:</strong> {finding['language'].upper()}</p>"
            
            if 'cwe' in finding:
                html += f"<p><strong>🔍 Reference:</strong> {finding['cwe']}</p>"
            
            if 'vulnerable_code' in finding:
                html += f"<p><strong>❌ Vulnerable Code:</strong></p>"
                html += f"<pre><code>{finding['vulnerable_code']}</code></pre>"
            
            if 'fix' in finding:
                html += f"""
        <div class="fix">
            <strong>✅ Fix Recommendation:</strong><br>
            {finding['fix']}
        </div>
"""
            
            html += "    </div>\n"
        
        html += """
</body>
</html>
"""
        return html

# ============================================================================
# MAIN SCANNER ORCHESTRATOR
# ============================================================================

class DeserializationScanner:
    """Main scanner orchestrator"""
    
    def __init__(self, args):
        self.args = args
        self.findings = []
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        try:
            log_level = logging.DEBUG if getattr(self.args, 'verbose', False) else logging.INFO
            log_format = '%(asctime)s - %(levelname)s - %(message)s'
            
            handlers = [logging.StreamHandler()]
            
            log_file = getattr(self.args, 'log_file', None)
            if log_file:
                try:
                    handlers.append(logging.FileHandler(log_file))
                except Exception as e:
                    print(f"Warning: Could not create log file: {e}")
            
            logging.basicConfig(
                level=log_level,
                format=log_format,
                handlers=handlers,
                force=True
            )
        except Exception as e:
            print(f"Warning: Logging setup failed: {e}")
    
    def run(self):
        """Main execution flow"""
        print(colored(BANNER, 'cyan', attrs=['bold']))
        
        if getattr(self.args, 'easy', False):
            self.run_easy_mode()
            return
        
        # Determine scan mode
        mode = getattr(self.args, 'mode', 'full')
        
        if mode == 'static' or (mode == 'full' and self._has_static_targets()):
            self.run_static_scan()
        
        if mode == 'dynamic' or (mode == 'full' and self._has_dynamic_targets()):
            self.run_dynamic_scan()
        
        if mode == 'full' and self._has_file_targets():
            self.run_file_scan()
        
        if mode == 'full' and self._has_pcap_target():
            self.run_pcap_scan()
        
        # Generate reports
        self.generate_reports()
    
    def run_easy_mode(self):
        """Interactive easy mode for beginners"""
        cprint("\n👋 Welcome to Easy Mode! Let's scan for insecure deserialization together!\n", 'cyan', attrs=['bold'])
        
        try:
            # Ask what to scan
            cprint("What would you like to scan?", 'yellow', attrs=['bold'])
            print("  1. A website or API (URL)")
            print("  2. Source code files")
            print("  3. A serialized file (.pkl, .ser, etc.)")
            print("  4. Network traffic (.pcap file)")
            
            choice = input("\n👉 Enter your choice (1-4): ").strip()
            
            if choice == '1':
                url = input("🌐 Enter the URL: ").strip()
                if url:
                    cprint(f"\n🔍 Scanning {url}...\n", 'cyan')
                    tester = DynamicTester(verbose=True)
                    self.findings = tester.test_url(url)
            
            elif choice == '2':
                path = input("📁 Enter file or directory path: ").strip()
                if os.path.exists(path):
                    cprint(f"\n🔍 Scanning {path}...\n", 'cyan')
                    analyzer = StaticAnalyzer(verbose=True)
                    if os.path.isdir(path):
                        self.findings = analyzer.analyze_directory(path)
                    else:
                        self.findings = analyzer.analyze_file(path)
                else:
                    cprint("❌ Path not found!", 'red')
                    return
            
            elif choice == '3':
                file_path = input("📄 Enter serialized file path: ").strip()
                if os.path.exists(file_path):
                    cprint(f"\n🔍 Analyzing {file_path}...\n", 'cyan')
                    analyzer = SerializedFileAnalyzer(verbose=True)
                    self.findings = analyzer.analyze_file(file_path)
                else:
                    cprint("❌ File not found!", 'red')
                    return
            
            elif choice == '4':
                pcap_file = input("📡 Enter PCAP file path: ").strip()
                if os.path.exists(pcap_file):
                    cprint(f"\n🔍 Analyzing network traffic...\n", 'cyan')
                    analyzer = NetworkTrafficAnalyzer(verbose=True)
                    self.findings = analyzer.analyze_pcap(pcap_file)
                else:
                    cprint("❌ File not found!", 'red')
                    return
            
            else:
                cprint("❌ Invalid choice!", 'red')
                return
            
            # Generate simple report
            report_gen = ReportGenerator(self.findings, verbose=False)
            report_gen.generate_console_report(simple=True)
            
            # Ask about saving report
            save = input("\n💾 Would you like to save a detailed report? (yes/no): ").strip().lower()
            if save in ['yes', 'y']:
                filename = input("📝 Enter filename (e.g., report.html): ").strip()
                if not filename:
                    filename = f"deserialization_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                
                if filename.endswith('.html'):
                    report_gen.generate_html_report(filename)
                elif filename.endswith('.json'):
                    report_gen.generate_json_report(filename)
                else:
                    report_gen.generate_html_report(filename + '.html')
        
        except KeyboardInterrupt:
            cprint("\n\n👋 Scan cancelled. Goodbye!", 'yellow')
        except Exception as e:
            cprint(f"\n❌ Oops! Something went wrong: {str(e)}", 'red')
            if getattr(self.args, 'verbose', False):
                import traceback
                traceback.print_exc()
    
    def run_static_scan(self):
        """Run static code analysis"""
        cprint("\n🔍 Running Static Code Analysis...\n", 'cyan', attrs=['bold'])
        
        try:
            analyzer = StaticAnalyzer(verbose=getattr(self.args, 'verbose', False))
            
            target = getattr(self.args, 'target', None)
            if not target:
                cprint("❌ No target specified", 'red')
                return
            
            if os.path.isfile(target):
                findings = analyzer.analyze_file(target)
            elif os.path.isdir(target):
                findings = analyzer.analyze_directory(target)
            else:
                cprint("❌ Invalid target for static analysis", 'red')
                return
            
            self.findings.extend(findings)
            cprint(f"✅ Static analysis complete. Found {len(findings)} issues.\n", 'green')
        except Exception as e:
            logging.error(f"Static scan error: {e}")
            cprint(f"❌ Static scan failed: {e}", 'red')
    
    def run_dynamic_scan(self):
        """Run dynamic testing"""
        cprint("\n🔍 Running Dynamic Vulnerability Testing...\n", 'cyan', attrs=['bold'])
        
        if not HAS_REQUESTS:
            cprint("❌ Dynamic testing requires 'requests' library", 'red')
            cprint("   Install with: pip install requests\n", 'yellow')
            return
        
        try:
            tester = DynamicTester(verbose=getattr(self.args, 'verbose', False))
            target = getattr(self.args, 'target', None)
            method = getattr(self.args, 'method', 'POST')
            
            if not target:
                cprint("❌ No target specified", 'red')
                return
            
            findings = tester.test_url(target, method=method)
            
            self.findings.extend(findings)
            cprint(f"✅ Dynamic testing complete. Found {len(findings)} issues.\n", 'green')
        except Exception as e:
            logging.error(f"Dynamic scan error: {e}")
            cprint(f"❌ Dynamic scan failed: {e}", 'red')
    
    def run_file_scan(self):
        """Run serialized file analysis"""
        cprint("\n🔍 Analyzing Serialized File...\n", 'cyan', attrs=['bold'])
        
        try:
            analyzer = SerializedFileAnalyzer(verbose=getattr(self.args, 'verbose', False))
            target = getattr(self.args, 'target', None)
            
            if not target:
                cprint("❌ No target specified", 'red')
                return
            
            findings = analyzer.analyze_file(target)
            
            self.findings.extend(findings)
            cprint(f"✅ File analysis complete. Found {len(findings)} issues.\n", 'green')
        except Exception as e:
            logging.error(f"File scan error: {e}")
            cprint(f"❌ File scan failed: {e}", 'red')
    
    def run_pcap_scan(self):
        """Run PCAP analysis"""
        cprint("\n🔍 Analyzing Network Traffic...\n", 'cyan', attrs=['bold'])
        
        try:
            analyzer = NetworkTrafficAnalyzer(verbose=getattr(self.args, 'verbose', False))
            target = getattr(self.args, 'target', None)
            
            if not target:
                cprint("❌ No target specified", 'red')
                return
            
            findings = analyzer.analyze_pcap(target)
            
            self.findings.extend(findings)
            cprint(f"✅ PCAP analysis complete. Found {len(findings)} issues.\n", 'green')
        except Exception as e:
            logging.error(f"PCAP scan error: {e}")
            cprint(f"❌ PCAP scan failed: {e}", 'red')
    
    def generate_reports(self):
        """Generate all requested reports"""
        try:
            report_gen = ReportGenerator(self.findings, verbose=getattr(self.args, 'verbose', False))
            
            # Console report
            simple = getattr(self.args, 'simple', False)
            report_gen.generate_console_report(simple=simple)
            
            # JSON report
            output_json = getattr(self.args, 'output_json', None)
            if output_json:
                report_gen.generate_json_report(output_json)
            
            # HTML report
            output_html = getattr(self.args, 'output_html', None)
            if output_html:
                report_gen.generate_html_report(output_html)
        except Exception as e:
            logging.error(f"Report generation error: {e}")
            cprint(f"❌ Failed to generate reports: {e}", 'red')
    
    def _has_static_targets(self) -> bool:
        """Check if target is suitable for static analysis"""
        target = getattr(self.args, 'target', None)
        if not target:
            return False
        return os.path.isfile(target) or os.path.isdir(target)
    
    def _has_dynamic_targets(self) -> bool:
        """Check if target is URL"""
        target = getattr(self.args, 'target', None)
        if not target:
            return False
        return target.startswith('http://') or target.startswith('https://')
    
    def _has_file_targets(self) -> bool:
        """Check if target is serialized file"""
        target = getattr(self.args, 'target', None)
        if not target or not os.path.isfile(target):
            return False
        ext = Path(target).suffix.lower()
        return ext in ['.pkl', '.pickle', '.ser', '.serialized', '.yaml', '.yml']
    
    def _has_pcap_target(self) -> bool:
        """Check if target is PCAP file"""
        target = getattr(self.args, 'target', None)
        if not target or not os.path.isfile(target):
            return False
        return Path(target).suffix.lower() in ['.pcap', '.pcapng', '.cap']

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description='Insecure Deserialization Scanner - Detect unsafe deserialization vulnerabilities',
        epilog='''
Examples:
  # Easy mode (interactive)
  python scanner.py --easy
  
  # Scan a website
  python scanner.py --target http://example.com/api --mode dynamic
  
  # Scan source code
  python scanner.py --target /path/to/code --mode static --type python
  
  # Full scan with reports
  python scanner.py --target /path/to/project --mode full --output-html report.html
  
  # Analyze serialized file
  python scanner.py --target suspicious.pkl --mode full
  
  # Analyze network traffic
  python scanner.py --target capture.pcap --mode full
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Main options
    parser.add_argument('--target', '-t', 
                       help='Target to scan (URL, file, or directory)')
    
    parser.add_argument('--type', '-y',
                       choices=['python', 'java', 'php', 'dotnet', 'ruby', 'nodejs', 'auto'],
                       default='auto',
                       help='Language type (default: auto-detect)')
    
    parser.add_argument('--mode', '-m',
                       choices=['static', 'dynamic', 'full'],
                       default='full',
                       help='Scan mode: static (code analysis), dynamic (live testing), full (both)')
    
    parser.add_argument('--method',
                       choices=['GET', 'POST', 'PUT'],
                       default='POST',
                       help='HTTP method for dynamic testing (default: POST)')
    
    # Easy mode
    parser.add_argument('--easy', '-e',
                       action='store_true',
                       help='Easy mode with interactive prompts (perfect for beginners!)')
    
    # Output options
    parser.add_argument('--output-json', '-oj',
                       help='Save report as JSON file')
    
    parser.add_argument('--output-html', '-oh',
                       help='Save report as HTML file')
    
    parser.add_argument('--simple', '-s',
                       action='store_true',
                       help='Simple output (beginner-friendly with emojis)')
    
    # Logging options
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Verbose output (show detailed progress)')
    
    parser.add_argument('--log-file', '-l',
                       help='Log file path')
    
    # Other options
    parser.add_argument('--timeout',
                       type=int,
                       default=10,
                       help='HTTP request timeout in seconds (default: 10)')
    
    parser.add_argument('--version',
                       action='version',
                       version=f'Insecure Deserialization Scanner v{VERSION}')
    
    return parser

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    # Disable SSL warnings for testing
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass
    
    parser = create_parser()
    args = parser.parse_args()
    
    # If no arguments, show help and enter easy mode prompt
    if len(sys.argv) == 1:
        print(colored(BANNER, 'cyan', attrs=['bold']))
        cprint("👋 Welcome! No arguments provided.\n", 'yellow', attrs=['bold'])
        cprint("Quick Start:", 'cyan', attrs=['bold'])
        print("  • Run easy mode: python scanner.py --easy")
        print("  • See all options: python scanner.py --help")
        print("  • Scan a URL: python scanner.py --target http://example.com")
        print("  • Scan code: python scanner.py --target /path/to/code\n")
        
        try:
            response = input("Would you like to start easy mode now? (yes/no): ").strip().lower()
            if response in ['yes', 'y']:
                args.easy = True
                args.target = None
                args.verbose = False
                args.simple = True
                args.mode = 'full'
            else:
                return
        except (EOFError, KeyboardInterrupt):
            print("\n👋 Goodbye!")
            return
    
    # Validate arguments
    if not getattr(args, 'easy', False) and not getattr(args, 'target', None):
        parser.error("--target is required (or use --easy for interactive mode)")
    
    try:
        scanner = DeserializationScanner(args)
        scanner.run()
    except KeyboardInterrupt:
        cprint("\n\n⚠️  Scan interrupted by user.", 'yellow')
        sys.exit(0)
    except Exception as e:
        cprint(f"\n❌ Fatal error: {str(e)}", 'red', attrs=['bold'])
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
