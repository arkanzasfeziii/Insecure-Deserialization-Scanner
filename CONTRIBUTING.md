# Contributing to Insecure Deserialization Scanner

Thank you for your interest in contributing! This document outlines guidelines to ensure smooth collaboration.

## 📌 Important Ethical Guidelines

- 🔒 **All payloads must be SAFE**: Never include actual exploit payloads that execute commands
- 🧪 **Testing only**: All test payloads must contain harmless markers (e.g., `DESERIAL_TEST_MARKER`)
- ⚖️ **Legal compliance**: Ensure all contributions comply with responsible disclosure practices
- 🚫 **No weaponization**: Do not add features designed to exploit vulnerabilities beyond detection

## 🛠️ Contribution Types

### 1. Adding New Language Support
- Create pattern definitions in `VulnerabilityPatterns` class
- Add payload generators in `PayloadGenerator`
- Implement file format detection in `SerializedFileAnalyzer`
- Include test cases with SAFE payloads only

### 2. Improving Detection Accuracy
- Reduce false positives with better regex patterns
- Add context-aware analysis (e.g., whitelist validation checks)
- Improve language detection heuristics

### 3. Reporting Enhancements
- New report formats (PDF, SARIF, etc.)
- Integration with CI/CD pipelines
- Vulnerability management system exports

## 🧪 Testing Requirements

All contributions MUST include:

```python
# Example safe test case
def test_safe_pickle_detection():
    """Test detection WITHOUT actual exploitation"""
    payload = PayloadGenerator.generate_python_pickle_payload()
    assert b"DESERIAL_TEST_MARKER" in payload
    # Never include actual command execution payloads
```
✅ Allowed: Safe marker payloads, signature detection
❌ Forbidden: Actual RCE payloads, command execution tests

🔒 Security Review Process
All pull requests undergo security review:
Payload safety verification
Ethical use assessment
Legal compliance check
False positive/negative analysis

📝 Code Style
Follow PEP 8 guidelines
Type hints required for new functions
Docstrings for all public methods
Comprehensive error handling
No external dependencies without security review

🚀 Submitting a Pull Request
Fork the repository
Create a feature branch (git checkout -b feature/description)
Commit changes (git commit -am 'Add feature')
Push to branch (git push origin feature/description)
Open a Pull Request with:
Clear description of changes
Safety assessment of any new payloads
Test results showing reduced false positives
Confirmation of ethical use compliance

⚠️ Critical Reminders
By contributing to this project, you confirm that:
All payloads are SAFE and non-exploitative
Your contributions comply with responsible disclosure ethics
You understand this tool must only be used with explicit authorization
You accept responsibility for legal compliance in your jurisdiction

💬 Questions?
Open a GitHub Issue with the label question or help wanted for guidance before implementing significant changes.
