# Password Cracker

A secure and efficient password cracking tool built with Python, designed for security research and educational purposes.

## ⚠️ Security Notice

This tool is intended for:
- Security research and penetration testing
- Educational purposes
- Authorized security assessments
- Password strength testing

**IMPORTANT**: Only use this tool on systems and accounts you own or have explicit permission to test. Unauthorized use may be illegal and unethical.

## 🚀 Features

- Multiple password cracking algorithms
  - Brute force
  - Dictionary-based attacks
  - Rainbow table support
- Support for various hash types
  - MD5
  - SHA-1
  - SHA-256
  - bcrypt
  - Argon2
- Parallel processing capabilities
- Comprehensive test coverage
- Security-focused development
- Progress tracking and reporting
- Configurable attack strategies

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Required system libraries (for cryptographic operations)

## 🛠️ Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-cracker.git
cd password-cracker
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🔧 Configuration

1. Copy the example configuration file:
```bash
cp config.example.yaml config.yaml
```

2. Edit `config.yaml` to customize:
- Attack strategies
- Thread count
- Dictionary paths
- Output settings

## 💻 Usage

Basic usage:
```bash
python password_cracker.py --hash <hash_value> --type <hash_type>
```

Advanced usage:
```bash
python password_cracker.py --hash <hash_value> --type <hash_type> --strategy <strategy> --threads <num_threads>
```

### Command Line Arguments

- `--hash`: The hash to crack
- `--type`: Hash type (md5, sha1, sha256, bcrypt, argon2)
- `--strategy`: Attack strategy (brute, dictionary, rainbow)
- `--threads`: Number of threads to use
- `--wordlist`: Path to custom wordlist
- `--output`: Output file path

## 🔒 Security Features

- Input validation and sanitization
- Secure error handling
- No debug statements in production
- Secure headers implementation
- Rate limiting
- Memory-safe operations
- Secure dependency management

## 🧪 Testing

Run the test suite:
```bash
python -m pytest tests/
```

Run security tests:
```bash
python -m pytest tests/security/
```

## 📊 Performance

- Optimized for multi-core systems
- Memory-efficient processing
- Configurable resource usage
- Progress tracking and reporting

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this program. Users are responsible for ensuring they have proper authorization before using this tool.

## 🔗 Links

- [Documentation](docs/)
- [Issue Tracker](https://github.com/yourusername/password-cracker/issues)
- [Security Policy](SECURITY.md)

## 📫 Contact

For security concerns, please email security@example.com

For general inquiries, please open an issue in the GitHub repository.