"""
Smoke tests for quick validation of Password Cracker functionality
"""
import pytest
import hashlib
from pathlib import Path

from basic_cracker import BasicCracker
from advanced_cracker import AdvancedCracker
from utils import hash_password, verify_password, validate_input
from web.app import app


@pytest.mark.smoke
class TestSmoke:
    """Quick smoke tests to verify basic functionality"""
    
    def test_basic_imports(self):
        """Test that all modules can be imported"""
        import base_cracker
        import basic_cracker
        import advanced_cracker
        import utils
        import config
        import web.app
        import web.middleware
        
        # If we get here, all imports worked
        assert True
    
    def test_basic_hash_generation(self):
        """Test basic hash generation works"""
        password = "testpassword"
        
        # Test different algorithms
        md5_hash = hash_password(password, 'md5')
        assert len(md5_hash) == 32
        
        sha256_hash = hash_password(password, 'sha256')
        assert len(sha256_hash) == 64
        
        bcrypt_hash = hash_password(password, 'bcrypt')
        assert bcrypt_hash.startswith('$2b$')
    
    def test_basic_verification(self):
        """Test password verification works"""
        password = "testpassword"
        
        # Generate and verify hash
        hash_value = hash_password(password, 'sha256')
        assert verify_password(password, hash_value, 'sha256') is True
        assert verify_password("wrongpassword", hash_value, 'sha256') is False
    
    def test_basic_validation(self):
        """Test input validation works"""
        # Valid inputs
        assert validate_input("ValidPassword123", "password") is True
        assert validate_input("a" * 64, "hash") is True
        
        # Invalid inputs should raise exception
        with pytest.raises(Exception):
            validate_input("short", "password")
        
        with pytest.raises(Exception):
            validate_input("invalid@hash", "hash")
    
    def test_basic_cracker_creation(self):
        """Test cracker objects can be created"""
        basic = BasicCracker('sha256')
        assert basic.algorithm == 'sha256'
        
        advanced = AdvancedCracker('md5')
        assert advanced.algorithm == 'md5'
    
    def test_web_app_starts(self):
        """Test web application can be created"""
        assert app is not None
        
        # Test client can be created
        app.config['TESTING'] = True
        client = app.test_client()
        assert client is not None
    
    def test_web_endpoints_exist(self):
        """Test main web endpoints exist"""
        app.config['TESTING'] = True
        client = app.test_client()
        
        # Test main page
        response = client.get('/')
        assert response.status_code in [200, 302, 404]  # Any of these is OK for smoke test
        
        # Test API endpoints exist
        endpoints = ['/api/analyze', '/api/hash', '/api/crack']
        for endpoint in endpoints:
            response = client.post(endpoint, json={})
            # Should get 400 (bad request) not 404 (not found)
            assert response.status_code in [400, 405, 200]
    
    def test_basic_crack_demo(self):
        """Test basic cracking in demo mode"""
        cracker = BasicCracker('md5')
        
        # Create a known hash
        password = "test123"
        target_hash = hashlib.md5(password.encode()).hexdigest()
        
        # Create temporary wordlist
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("wrong1\nwrong2\ntest123\nwrong3\n")
            wordlist_path = Path(f.name)
        
        try:
            # Try to crack it
            result = cracker.crack_hash(target_hash, wordlist_path)
            assert result == password
        finally:
            # Cleanup
            wordlist_path.unlink()
    
    def test_config_loaded(self):
        """Test configuration is loaded properly"""
        from config import (
            MAX_ATTEMPTS, RATE_LIMIT, MAX_THREADS, TIMEOUT,
            SUPPORTED_HASHES, ERROR_MESSAGES, SUCCESS_MESSAGES
        )
        
        # Check key config values exist
        assert MAX_ATTEMPTS > 0
        assert RATE_LIMIT > 0
        assert MAX_THREADS > 0
        assert TIMEOUT > 0
        assert len(SUPPORTED_HASHES) > 0
        assert len(ERROR_MESSAGES) > 0
        assert len(SUCCESS_MESSAGES) > 0
    
    def test_directories_exist(self):
        """Test required directories exist or can be created"""
        from config import WORDLISTS_DIR, RESULTS_DIR, LOGS_DIR
        
        # These should exist or be creatable
        for directory in [WORDLISTS_DIR, RESULTS_DIR, LOGS_DIR]:
            assert directory.exists() or directory.parent.exists()
    
    @pytest.mark.smoke
    def test_error_handling(self):
        """Test basic error handling works"""
        from utils import SecurityError
        
        # Test custom exception
        with pytest.raises(SecurityError):
            raise SecurityError("Test error")
        
        # Test validation errors
        with pytest.raises(SecurityError):
            validate_input("", "password")
    
    def test_logging_configured(self):
        """Test logging is properly configured"""
        import logging
        
        logger = logging.getLogger(__name__)
        
        # Should be able to log without errors
        logger.info("Smoke test info message")
        logger.warning("Smoke test warning message")
        logger.error("Smoke test error message")
        
        # If we get here, logging works
        assert True