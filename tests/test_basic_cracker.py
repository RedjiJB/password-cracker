"""
Unit tests for basic_cracker.py
"""
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open
import sys
import time

from basic_cracker import BasicCracker, main
from utils import SecurityError
from config import WORDLISTS_DIR, RESULTS_DIR


class TestBasicCracker:
    """Test suite for BasicCracker class"""
    
    @pytest.fixture
    def cracker(self):
        """Create a BasicCracker instance"""
        return BasicCracker('sha256')
    
    @pytest.fixture
    def temp_wordlist(self, tmp_path):
        """Create a temporary wordlist file"""
        wordlist = tmp_path / "test_wordlist.txt"
        wordlist.write_text("password\n123456\nadmin\nletmein\nmonkey\n")
        return wordlist
    
    @pytest.fixture
    def temp_hash_file(self, tmp_path):
        """Create a temporary hash file"""
        hash_file = tmp_path / "test_hashes.txt"
        hash_file.write_text(
            "5f4dcc3b5aa765d61d8327deb882cf99\n"  # MD5 of 'password'
            "7c222fb2927d828af22f592134e8932480637c0d\n"  # SHA1 of '12345678'
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"  # SHA256 of ''
        )
        return hash_file
    
    def test_initialization(self):
        """Test BasicCracker initialization"""
        cracker = BasicCracker('md5')
        assert cracker.algorithm == 'md5'
        assert cracker.attempts == 0
        assert cracker.start_time == 0
    
    @patch.object(BasicCracker, 'validate_hash')
    @patch.object(BasicCracker, 'load_wordlist')
    @patch.object(BasicCracker, 'check_password')
    def test_crack_hash_success(self, mock_check, mock_load, mock_validate, cracker):
        """Test successful hash cracking"""
        mock_validate.return_value = True
        mock_load.return_value = ['password', '123456', 'admin']
        mock_check.side_effect = [False, True, False]  # Second password matches
        
        result = cracker.crack_hash('test_hash', Path('wordlist.txt'))
        
        assert result == '123456'
        assert 'test_hash' in cracker.found_passwords
        assert cracker.found_passwords['test_hash'] == '123456'
        mock_validate.assert_called_once_with('test_hash')
        mock_load.assert_called_once()
        assert mock_check.call_count == 2
    
    @patch.object(BasicCracker, 'validate_hash')
    @patch.object(BasicCracker, 'load_wordlist')
    @patch.object(BasicCracker, 'check_password')
    def test_crack_hash_not_found(self, mock_check, mock_load, mock_validate, cracker):
        """Test hash cracking when password not found"""
        mock_validate.return_value = True
        mock_load.return_value = ['password', '123456', 'admin']
        mock_check.return_value = False  # No matches
        
        result = cracker.crack_hash('test_hash', Path('wordlist.txt'))
        
        assert result is None
        assert 'test_hash' not in cracker.found_passwords
        assert mock_check.call_count == 3
    
    @patch.object(BasicCracker, 'validate_hash')
    @patch.object(BasicCracker, 'load_wordlist')
    @patch.object(BasicCracker, 'check_password')
    @patch.object(BasicCracker, 'check_timeout')
    def test_crack_hash_timeout(self, mock_timeout, mock_check, mock_load, mock_validate, cracker):
        """Test hash cracking with timeout"""
        mock_validate.return_value = True
        mock_load.return_value = ['password', '123456', 'admin']
        mock_check.return_value = False
        mock_timeout.side_effect = [False, True]  # Timeout on second check
        
        result = cracker.crack_hash('test_hash', Path('wordlist.txt'))
        
        assert result is None
        assert mock_check.call_count == 1
    
    @patch.object(BasicCracker, 'validate_hash')
    @patch.object(BasicCracker, 'load_wordlist')
    @patch.object(BasicCracker, 'check_password')
    @patch.object(BasicCracker, 'check_attempts')
    def test_crack_hash_max_attempts(self, mock_attempts, mock_check, mock_load, mock_validate, cracker):
        """Test hash cracking with max attempts reached"""
        mock_validate.return_value = True
        mock_load.return_value = ['password', '123456', 'admin']
        mock_check.return_value = False
        mock_attempts.side_effect = [False, True]  # Max attempts on second check
        
        result = cracker.crack_hash('test_hash', Path('wordlist.txt'))
        
        assert result is None
        assert mock_check.call_count == 1
    
    @patch.object(BasicCracker, 'validate_hash')
    def test_crack_hash_invalid_hash(self, mock_validate, cracker):
        """Test hash cracking with invalid hash"""
        mock_validate.side_effect = SecurityError("Invalid hash")
        
        with pytest.raises(SecurityError) as exc_info:
            cracker.crack_hash('invalid', Path('wordlist.txt'))
        assert "Failed to crack hash" in str(exc_info.value)
    
    @patch.object(BasicCracker, 'validate_hash')
    @patch.object(BasicCracker, 'load_wordlist')
    def test_crack_hash_wordlist_error(self, mock_load, mock_validate, cracker):
        """Test hash cracking with wordlist loading error"""
        mock_validate.return_value = True
        mock_load.side_effect = SecurityError("Failed to load wordlist")
        
        with pytest.raises(SecurityError) as exc_info:
            cracker.crack_hash('test_hash', Path('wordlist.txt'))
        assert "Failed to crack hash" in str(exc_info.value)
    
    @patch('basic_cracker.secure_file_operation')
    @patch.object(BasicCracker, 'crack_hash')
    @patch.object(BasicCracker, 'save_results')
    def test_crack_multiple_success(self, mock_save, mock_crack, mock_file_op, cracker):
        """Test cracking multiple hashes successfully"""
        mock_file_op.return_value = "hash1\nhash2\nhash3\n"
        mock_crack.side_effect = ['password1', None, 'password3']
        
        cracker.crack_multiple(Path('hashes.txt'), Path('wordlist.txt'))
        
        assert mock_crack.call_count == 3
        assert len(cracker.found_passwords) == 2
        assert cracker.found_passwords['hash1'] == 'password1'
        assert cracker.found_passwords['hash3'] == 'password3'
        mock_save.assert_called_once()
    
    @patch('basic_cracker.secure_file_operation')
    @patch.object(BasicCracker, 'crack_hash')
    def test_crack_multiple_no_results(self, mock_crack, mock_file_op, cracker):
        """Test cracking multiple hashes with no results"""
        mock_file_op.return_value = "hash1\nhash2\n"
        mock_crack.return_value = None
        
        cracker.crack_multiple(Path('hashes.txt'), Path('wordlist.txt'))
        
        assert mock_crack.call_count == 2
        assert len(cracker.found_passwords) == 0
    
    @patch('basic_cracker.secure_file_operation')
    def test_crack_multiple_file_error(self, mock_file_op, cracker):
        """Test cracking multiple hashes with file error"""
        mock_file_op.side_effect = Exception("File error")
        
        with pytest.raises(SecurityError) as exc_info:
            cracker.crack_multiple(Path('hashes.txt'), Path('wordlist.txt'))
        assert "Failed to crack multiple hashes" in str(exc_info.value)
    
    def test_crack_hash_with_stop_flag(self, cracker):
        """Test hash cracking with stop flag set"""
        cracker.stop_flag.set()
        
        with patch.object(cracker, 'validate_hash'):
            with patch.object(cracker, 'load_wordlist', return_value=['password']):
                result = cracker.crack_hash('test_hash', Path('wordlist.txt'))
        
        assert result is None


class TestMainFunction:
    """Test suite for main function"""
    
    @patch('sys.argv', ['basic_cracker.py', 'generate', '-a', 'md5'])
    @patch('basic_cracker.hash_password')
    def test_main_generate_mode(self, mock_hash, capsys):
        """Test main function in generate mode"""
        mock_hash.side_effect = lambda pwd, alg: f"{alg}_{pwd}"
        
        main()
        
        captured = capsys.readouterr()
        assert "PASSWORD CRACKER v1.0" in captured.out
        assert "Generating sample hashes" in captured.out
        assert "password" in captured.out
        assert "md5_password" in captured.out
        assert mock_hash.call_count == 10
    
    @patch('sys.argv', ['basic_cracker.py', 'demo', '-a', 'sha256'])
    @patch('basic_cracker.hash_password')
    @patch.object(BasicCracker, 'crack_hash')
    def test_main_demo_mode_success(self, mock_crack, mock_hash, capsys):
        """Test main function in demo mode with success"""
        mock_hash.return_value = 'demo_hash'
        mock_crack.return_value = 'password'
        
        main()
        
        captured = capsys.readouterr()
        assert "Running demo mode" in captured.out
        assert "Successfully cracked: password" in captured.out
    
    @patch('sys.argv', ['basic_cracker.py', 'demo', '-a', 'sha256'])
    @patch('basic_cracker.hash_password')
    @patch.object(BasicCracker, 'crack_hash')
    def test_main_demo_mode_failure(self, mock_crack, mock_hash, capsys):
        """Test main function in demo mode with failure"""
        mock_hash.return_value = 'demo_hash'
        mock_crack.return_value = None
        
        main()
        
        captured = capsys.readouterr()
        assert "Running demo mode" in captured.out
        assert "Demo completed without finding password" in captured.out
    
    @patch('sys.argv', ['basic_cracker.py', 'crack', '-t', 'target_hash'])
    @patch.object(BasicCracker, 'crack_hash')
    def test_main_crack_mode_single_hash_success(self, mock_crack, capsys):
        """Test main function in crack mode with single hash success"""
        mock_crack.return_value = 'found_password'
        
        main()
        
        captured = capsys.readouterr()
        assert "Password found: found_password" in captured.out
    
    @patch('sys.argv', ['basic_cracker.py', 'crack', '-t', 'target_hash'])
    @patch.object(BasicCracker, 'crack_hash')
    def test_main_crack_mode_single_hash_failure(self, mock_crack, capsys):
        """Test main function in crack mode with single hash failure"""
        mock_crack.return_value = None
        
        main()
        
        captured = capsys.readouterr()
        assert "Password not found in wordlist" in captured.out
    
    @patch('sys.argv', ['basic_cracker.py', 'crack', '-f', 'hashes.txt'])
    @patch.object(BasicCracker, 'crack_multiple')
    def test_main_crack_mode_file(self, mock_crack_multiple):
        """Test main function in crack mode with hash file"""
        main()
        mock_crack_multiple.assert_called_once()
    
    @patch('sys.argv', ['basic_cracker.py', 'crack'])
    def test_main_crack_mode_no_input(self, capsys):
        """Test main function in crack mode with no input"""
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        
        captured = capsys.readouterr()
        assert "Please provide a target hash" in captured.out
    
    @patch('sys.argv', ['basic_cracker.py', 'invalid'])
    def test_main_invalid_mode(self):
        """Test main function with invalid mode"""
        with pytest.raises(SystemExit):
            main()
    
    @patch('sys.argv', ['basic_cracker.py', 'crack', '-t', 'hash'])
    @patch.object(BasicCracker, 'crack_hash')
    def test_main_security_error(self, mock_crack, capsys):
        """Test main function with security error"""
        mock_crack.side_effect = SecurityError("Test security error")
        
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        
        captured = capsys.readouterr()
        assert "Security Error: Test security error" in captured.out
    
    @patch('sys.argv', ['basic_cracker.py', 'crack', '-t', 'hash'])
    @patch.object(BasicCracker, 'crack_hash')
    def test_main_keyboard_interrupt(self, mock_crack, capsys):
        """Test main function with keyboard interrupt"""
        mock_crack.side_effect = KeyboardInterrupt()
        
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        
        captured = capsys.readouterr()
        assert "Operation cancelled by user" in captured.out
    
    @patch('sys.argv', ['basic_cracker.py', 'crack', '-t', 'hash'])
    @patch.object(BasicCracker, 'crack_hash')
    def test_main_general_exception(self, mock_crack, capsys):
        """Test main function with general exception"""
        mock_crack.side_effect = Exception("Test error")
        
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        
        captured = capsys.readouterr()
        assert "Error: Test error" in captured.out
    
    @patch('sys.argv', ['basic_cracker.py', 'crack', '-t', 'hash', '-a', 'bcrypt'])
    @patch.object(BasicCracker, 'crack_hash')
    def test_main_with_algorithm(self, mock_crack):
        """Test main function with custom algorithm"""
        mock_crack.return_value = None
        
        with patch.object(BasicCracker, '__init__', return_value=None) as mock_init:
            mock_init.return_value = None
            main()
            
            # Verify BasicCracker was initialized with bcrypt
            mock_init.assert_called_with('bcrypt')