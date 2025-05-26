"""
Pytest configuration and fixtures for Password Cracker tests
"""
import pytest
import sys
import os
from pathlib import Path
import tempfile
import shutil
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "performance: mark test as a performance test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security-focused"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )


@pytest.fixture(scope="session")
def test_data_dir():
    """Create a temporary directory for test data that persists for the session"""
    temp_dir = tempfile.mkdtemp(prefix="password_cracker_test_")
    yield Path(temp_dir)
    # Cleanup after all tests
    shutil.rmtree(temp_dir)


@pytest.fixture(scope="function")
def temp_dir():
    """Create a temporary directory for each test"""
    temp_dir = tempfile.mkdtemp(prefix="pc_test_")
    yield Path(temp_dir)
    # Cleanup after test
    shutil.rmtree(temp_dir)


@pytest.fixture(scope="session")
def sample_wordlist(test_data_dir):
    """Create a sample wordlist for testing"""
    wordlist_path = test_data_dir / "sample_wordlist.txt"
    passwords = [
        "password", "123456", "password123", "admin", "letmein",
        "monkey", "1234567890", "qwerty", "abc123", "Password1",
        "password1", "123456789", "welcome", "1234567", "login",
        "admin123", "root", "toor", "pass", "test", "guest",
        "master", "hello", "hello123", "three", "password123!"
    ]
    wordlist_path.write_text("\n".join(passwords))
    return wordlist_path


@pytest.fixture(scope="session")
def sample_hashes(test_data_dir):
    """Create sample hashes for testing"""
    import hashlib
    
    hashes_path = test_data_dir / "sample_hashes.txt"
    passwords = ["password", "admin", "test123"]
    hashes = []
    
    for pwd in passwords:
        # MD5
        hashes.append(hashlib.md5(pwd.encode()).hexdigest())
        # SHA256
        hashes.append(hashlib.sha256(pwd.encode()).hexdigest())
    
    hashes_path.write_text("\n".join(hashes))
    return hashes_path


@pytest.fixture(autouse=True)
def reset_logging():
    """Reset logging configuration for each test"""
    # Clear all handlers
    logger = logging.getLogger()
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Set to WARNING to reduce test output noise
    logging.basicConfig(level=logging.WARNING)
    
    yield
    
    # Clear handlers again after test
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)


@pytest.fixture
def mock_config(monkeypatch):
    """Mock configuration values for testing"""
    monkeypatch.setattr("config.MAX_ATTEMPTS", 1000)
    monkeypatch.setattr("config.RATE_LIMIT", 100)
    monkeypatch.setattr("config.MAX_THREADS", 4)
    monkeypatch.setattr("config.TIMEOUT", 10)


@pytest.fixture
def disable_rate_limiting(monkeypatch):
    """Disable rate limiting for tests that don't need it"""
    def no_rate_limit(func):
        return func
    
    monkeypatch.setattr("utils.rate_limit", no_rate_limit)


@pytest.fixture
def fast_bcrypt(monkeypatch):
    """Use fast bcrypt settings for testing"""
    import bcrypt
    
    original_gensalt = bcrypt.gensalt
    
    def fast_gensalt(rounds=4):  # Use low rounds for testing
        return original_gensalt(rounds=4)
    
    monkeypatch.setattr("bcrypt.gensalt", fast_gensalt)


# Test environment setup
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names"""
    for item in items:
        # Add markers based on test file names
        if "test_performance" in str(item.fspath):
            item.add_marker(pytest.mark.performance)
        elif "test_security" in str(item.fspath):
            item.add_marker(pytest.mark.security)
        elif "test_integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Mark slow tests
        if "stress_test" in item.name or "large_scale" in item.name:
            item.add_marker(pytest.mark.slow)


# Pytest plugins and hooks
def pytest_runtest_setup(item):
    """Setup for each test run"""
    # Skip slow tests unless explicitly requested
    if "slow" in item.keywords and not item.config.getoption("--runslow"):
        pytest.skip("need --runslow option to run slow tests")


def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption(
        "--runslow", action="store_true", default=False, help="run slow tests"
    )
    parser.addoption(
        "--performance", action="store_true", default=False, 
        help="run only performance tests"
    )
    parser.addoption(
        "--security", action="store_true", default=False,
        help="run only security tests"
    )