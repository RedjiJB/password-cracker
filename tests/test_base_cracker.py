"""
Unit tests for base_cracker.py
"""
import pytest
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import threading
import json

from base_cracker import BaseCracker
from utils import SecurityError
from config import MAX_ATTEMPTS, TIMEOUT, SUPPORTED_HASHES


class TestBaseCracker(BaseCracker):
    """Concrete implementation of BaseCracker for testing"""
    
    def crack_hash(self, target_hash: str, wordlist_path: Path):
        """Mock implementation for testing"""
        return "password123" if target_hash == "test_hash" else None


class TestBaseCrackerClass:
    """Test suite for BaseCracker class"""
    
    @pytest.fixture
    def cracker(self):
        """Create a test cracker instance"""
        return TestBaseCracker('sha256')
    
    @pytest.fixture
    def temp_wordlist(self, tmp_path):
        """Create a temporary wordlist file"""
        wordlist = tmp_path / "test_wordlist.txt"
        wordlist.write_text("password\n123456\nadmin\nletmein\n")
        return wordlist
    
    @pytest.fixture
    def temp_results_dir(self, tmp_path):
        """Create a temporary results directory"""
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        return results_dir
    
    def test_initialization(self):
        """Test BaseCracker initialization"""
        # Test valid algorithm
        cracker = TestBaseCracker('sha256')
        assert cracker.algorithm == 'sha256'
        assert cracker.attempts == 0
        assert cracker.start_time == 0
        assert isinstance(cracker.stop_flag, threading.Event)
        assert isinstance(cracker.lock, threading.Lock)
        assert isinstance(cracker.found_passwords, dict)
        assert isinstance(cracker.rate_limiter, threading.Semaphore)
        
        # Test invalid algorithm
        with pytest.raises(SecurityError) as exc_info:
            TestBaseCracker('invalid_algorithm')
        assert "Unsupported algorithm" in str(exc_info.value)
    
    def test_validate_hash(self, cracker):
        """Test hash validation"""
        # Test valid hashes
        valid_hashes = [
            '5f4dcc3b5aa765d61d8327deb882cf99',  # MD5
            'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',  # SHA256
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' * 2  # SHA512
        ]
        
        for hash_value in valid_hashes:
            assert cracker.validate_hash(hash_value) is True
        
        # Test invalid hashes
        invalid_hashes = [
            '',
            'short',
            'invalid@hash!',
            '123',
            'g' * 32  # Invalid hex
        ]
        
        for hash_value in invalid_hashes:
            with pytest.raises(SecurityError):
                cracker.validate_hash(hash_value)
    
    @patch('base_cracker.verify_password')
    def test_check_password(self, mock_verify, cracker):
        """Test password checking"""
        mock_verify.return_value = True
        
        # Test successful check
        result = cracker.check_password('password', 'test_hash')
        assert result is True
        assert cracker.attempts == 1
        mock_verify.assert_called_once_with('password', 'test_hash', 'sha256')
        
        # Test failed check
        mock_verify.return_value = False
        result = cracker.check_password('wrong', 'test_hash')
        assert result is False
        assert cracker.attempts == 2
    
    @patch('base_cracker.verify_password')
    def test_check_password_exception(self, mock_verify, cracker):
        """Test password checking with exception"""
        mock_verify.side_effect = Exception("Test error")
        
        result = cracker.check_password('password', 'test_hash')
        assert result is False
    
    @patch('base_cracker.secure_file_operation')
    def test_load_wordlist(self, mock_file_op, cracker):
        """Test wordlist loading"""
        mock_file_op.return_value = "password\n123456\nadmin\n<script>alert('xss')</script>\n"
        
        passwords = cracker.load_wordlist(Path("test.txt"))
        
        # Should filter out invalid passwords
        assert len(passwords) == 3
        assert 'password' in passwords
        assert '123456' in passwords
        assert 'admin' in passwords
        assert "<script>alert('xss')</script>" not in passwords
    
    @patch('base_cracker.secure_file_operation')
    def test_load_wordlist_error(self, mock_file_op, cracker):
        """Test wordlist loading with error"""
        mock_file_op.side_effect = Exception("File error")
        
        with pytest.raises(SecurityError) as exc_info:
            cracker.load_wordlist(Path("test.txt"))
        assert "Failed to load wordlist" in str(exc_info.value)
    
    def test_check_timeout(self, cracker):
        """Test timeout checking"""
        # No timeout initially
        cracker.start_time = time.time()
        assert cracker.check_timeout() is False
        
        # Simulate timeout
        cracker.start_time = time.time() - TIMEOUT - 1
        assert cracker.check_timeout() is True
    
    def test_check_attempts(self, cracker):
        """Test attempts checking"""
        # Under limit
        cracker.attempts = MAX_ATTEMPTS - 1
        assert cracker.check_attempts() is False
        
        # At limit
        cracker.attempts = MAX_ATTEMPTS
        assert cracker.check_attempts() is True
        
        # Over limit
        cracker.attempts = MAX_ATTEMPTS + 1
        assert cracker.check_attempts() is True
    
    def test_save_results(self, cracker, temp_results_dir):
        """Test results saving"""
        cracker.algorithm = 'sha256'
        cracker.attempts = 100
        cracker.start_time = time.time() - 10
        cracker.found_passwords = {
            'hash1': 'password1',
            'hash2': 'password2'
        }
        
        output_path = temp_results_dir / "test_results.json"
        cracker.save_results(output_path)
        
        # Verify file was created and contains expected data
        assert output_path.exists()
        
        with open(output_path, 'r') as f:
            results = json.load(f)
        
        assert results['algorithm'] == 'sha256'
        assert results['attempts'] == 100
        assert 'time_elapsed' in results
        assert results['time_elapsed'] >= 10
        assert 'found_passwords' in results
    
    def test_save_results_error(self, cracker):
        """Test results saving with error"""
        with pytest.raises(SecurityError) as exc_info:
            cracker.save_results(Path("/invalid/path/results.json"))
        assert "Failed to save results" in str(exc_info.value)
    
    @patch('base_cracker.log_security_event')
    def test_log_attempt(self, mock_log, cracker):
        """Test attempt logging"""
        cracker.attempts = 5
        cracker.start_time = time.time() - 10
        
        cracker.log_attempt('testpass', True)
        
        mock_log.assert_called_once()
        call_args = mock_log.call_args[0]
        assert call_args[0] == 'password_attempt'
        assert call_args[1]['password'] == 'testpass'
        assert call_args[1]['success'] is True
        assert call_args[1]['attempts'] == 5
        assert 'time_elapsed' in call_args[1]
    
    def test_cleanup(self, cracker):
        """Test cleanup method"""
        cracker.attempts = 100
        cracker.found_passwords = {'hash': 'password'}
        cracker.stop_flag.clear()
        
        cracker.cleanup()
        
        assert cracker.stop_flag.is_set()
        assert cracker.attempts == 0
        assert len(cracker.found_passwords) == 0
    
    def test_rate_limiting(self, cracker):
        """Test rate limiting functionality"""
        # Acquire rate limiter multiple times
        initial_count = cracker.rate_limiter._value
        
        with cracker.rate_limiter:
            assert cracker.rate_limiter._value == initial_count - 1
        
        assert cracker.rate_limiter._value == initial_count
    
    def test_thread_safety(self, cracker):
        """Test thread safety with lock"""
        def increment_attempts():
            with cracker.lock:
                current = cracker.attempts
                time.sleep(0.001)  # Simulate some work
                cracker.attempts = current + 1
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=increment_attempts)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert cracker.attempts == 10
    
    def test_abstract_method_implementation(self):
        """Test that abstract method must be implemented"""
        with pytest.raises(TypeError):
            # Can't instantiate abstract class without implementing crack_hash
            BaseCracker('sha256')