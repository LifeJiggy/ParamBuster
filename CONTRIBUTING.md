# Contributing to ParamBuster

Thank you for your interest in contributing to ParamBuster! We welcome contributions from the security research community. This document provides guidelines for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## 🤝 Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. By participating, you agree to:

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Show empathy towards other contributors
- Help create a positive community

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Git
- Chrome browser (for browser mode testing)
- Basic understanding of web security concepts

### Fork and Clone
```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/ParamBuster.git
cd ParamBuster

# Set up upstream remote
git remote add upstream https://github.com/LifeJiggy/ParamBuster.git
```

## 🛠️ Development Setup

### Install Dependencies
```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

### Create Virtual Environment (Recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Run Tests
```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest tests/test_param_detection.py

# Run with coverage
python -m pytest --cov=ParamBuster --cov-report=html
```

### Code Quality Checks
```bash
# Run linting
flake8 ParamBuster.py

# Run type checking
mypy ParamBuster.py

# Format code
black ParamBuster.py
```

## 📝 Contributing Guidelines

### Code Standards

#### Python Style
- Follow [PEP 8](https://pep8.org/) style guidelines
- Use 4 spaces for indentation
- Maximum line length: 88 characters (Black formatter default)
- Use descriptive variable and function names

#### Type Hints
```python
def detect_parameters(self, response: requests.Response) -> Dict[str, Any]:
    """Detect parameters with reflection analysis."""
    pass
```

#### Docstrings
```python
def scan_vulnerabilities(self, param: str) -> Dict[str, Dict[str, Any]]:
    """
    Scan a parameter for multiple vulnerability types.

    Args:
        param: The parameter name to test

    Returns:
        Dictionary containing vulnerability findings

    Raises:
        RequestException: If network requests fail
    """
    pass
```

### Commit Messages
Use clear, descriptive commit messages:
```
feat: add support for custom payload directories
fix: resolve memory leak in browser mode
docs: update installation instructions
test: add unit tests for parameter extraction
```

### Branch Naming
- `feature/description`: New features
- `fix/description`: Bug fixes
- `docs/description`: Documentation updates
- `test/description`: Test additions/updates

## 🧪 Testing

### Unit Tests
Create comprehensive unit tests for new features:

```python
# tests/test_new_feature.py
import pytest
from ParamBuster import ParamBuster

class TestNewFeature:
    def test_feature_basic_functionality(self):
        scanner = ParamBuster("https://example.com")
        result = scanner.new_feature()
        assert result is not None

    def test_feature_with_edge_cases(self):
        scanner = ParamBuster("https://example.com")
        # Test edge cases
        pass
```

### Integration Tests
Test complete workflows:

```python
def test_full_parameter_scan():
    scanner = ParamBuster("https://httpbin.org")
    results = scanner.run()
    assert "parameters" in results
    assert isinstance(results["parameters"], dict)
```

### Manual Testing
For complex features, provide manual testing instructions in PR descriptions.

## 🔄 Submitting Changes

### Pull Request Process

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write clean, well-documented code
   - Add/update tests
   - Update documentation if needed

3. **Run Tests**
   ```bash
   python -m pytest
   flake8 ParamBuster.py
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   # Create PR on GitHub
   ```

### PR Template
Use this template for pull requests:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows PEP 8 style
- [ ] Type hints added for new functions
- [ ] Documentation updated
- [ ] Tests pass locally
- [ ] No breaking changes
```

## 🐛 Reporting Issues

### Bug Reports
Use the bug report template:

```markdown
**Describe the bug**
Clear description of the issue

**To Reproduce**
Steps to reproduce:
1. Run command: `python ParamBuster.py -u https://example.com`
2. Observe error...

**Expected behavior**
What should happen

**Environment**
- OS: [e.g., Windows 10]
- Python version: [e.g., 3.9]
- ParamBuster version: [e.g., v7.0]

**Additional context**
Any other relevant information
```

### Feature Requests
Use the feature request template:

```markdown
**Is your feature request related to a problem?**
Describe the problem

**Describe the solution you'd like**
Clear description of the proposed feature

**Describe alternatives you've considered**
Other solutions or workarounds

**Additional context**
Screenshots, examples, or references
```

## 🎯 Areas for Contribution

### High Priority
- [ ] Performance optimizations
- [ ] Additional vulnerability types
- [ ] Better WAF bypass techniques
- [ ] Enhanced browser automation features

### Medium Priority
- [ ] GUI interface
- [ ] Plugin system for custom scanners
- [ ] Integration with other security tools
- [ ] Advanced reporting features

### Low Priority
- [ ] Mobile app support
- [ ] Cloud deployment options
- [ ] Machine learning-based detection

## 📚 Resources

### Learning Resources
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Python Security Best Practices](https://github.com/PyCQA/bandit)

### Similar Tools
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [Arjun](https://github.com/s0md3v/Arjun)
- [Dirsearch](https://github.com/maurosoria/dirsearch)

## 📞 Getting Help

- **Issues**: [GitHub Issues](https://github.com/LifeJiggy/ParamBuster/issues)
- **Discussions**: [GitHub Discussions](https://github.com/LifeJiggy/ParamBuster/discussions)
- **Documentation**: [Wiki](https://github.com/LifeJiggy/ParamBuster/wiki)

## 🙏 Recognition

Contributors will be recognized in:
- README.md contributors section
- CHANGELOG.md
- GitHub release notes

Thank you for contributing to ParamBuster! 🐞