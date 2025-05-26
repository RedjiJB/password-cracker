"""
Unit tests for advanced_cracker.py
"""
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
import sys
import time
import string
from concurrent.futures import Future

from advanced_cracker import AdvancedCracker, main
from utils import SecurityError
from config import MAX_THREADS, WORDLISTS_DIR


class TestAdvancedCracker:
    """Test suite for AdvancedCracker class"""
    
    @pytest.fixture
    def cracker(self):
        """Create an AdvancedCracker instance"""
        return AdvancedCracker('sha256')
    
    @pytest.fixture
    def temp_wordlist(self, tmp_path):
        """Create a temporary wordlist file"""
        wordlist = tmp_path / "test_wordlist.txt"
        wordlist.write_text("password\n123456\nadmin\nletmein\n")
        return wordlist
    
    def test_initialization(self):
        """Test AdvancedCracker initialization"""
        cracker = AdvancedCracker('md5')
        assert cracker.algorithm == 'md5'
        assert isinstance(cracker.character_sets, dict)
        assert 'lowercase' in cracker.character_sets
        assert 'uppercase' in cracker.character_sets
        assert 'digits' in cracker.character_sets
        assert 'special' in cracker.character_sets
        assert isinstance(cracker.known_patterns, dict)
        assert 'dates' in cracker.known_patterns
        assert 'common_words' in cracker.known_patterns
        assert 'keyboard_patterns' in cracker.known_patterns
    
    def test_generate_date_patterns(self, cracker):
        """Test date pattern generation"""
        patterns = cracker._generate_date_patterns()
        
        assert isinstance(patterns, set)
        assert len(patterns) > 0
        
        # Check some specific patterns
        assert '20230101' in patterns  # YYYYMMDD
        assert '01012023' in patterns  # DDMMYYYY
    
    @patch('builtins.open', new_callable=mock_open, read_data="test\npassword\nadmin\n")
    def test_load_common_words(self, mock_file):
        """Test loading common words"""
        cracker = AdvancedCracker('sha256')
        words = cracker._load_common_words()
        
        # Should be empty since the file doesn't exist in test environment
        assert isinstance(words, set)
    
    def test_generate_keyboard_patterns(self, cracker):
        """Test keyboard pattern generation"""
        patterns = cracker._generate_keyboard_patterns()
        
        assert isinstance(patterns, set)
        assert len(patterns) > 0
        
        # Check some specific patterns
        assert 'qwe' in patterns  # Horizontal pattern
        assert 'asd' in patterns  # Horizontal pattern
        assert 'zxc' in patterns  # Horizontal pattern
    
    @patch.object(AdvancedCracker, 'validate_hash')
    @patch.object(AdvancedCracker, 'load_wordlist')
    @patch.object(AdvancedCracker, '_try_wordlist')
    @patch.object(AdvancedCracker, '_try_patterns')
    @patch.object(AdvancedCracker, '_try_brute_force')
    def test_crack_hash_wordlist_success(self, mock_brute, mock_patterns, mock_wordlist, mock_load, mock_validate, cracker):
        """Test successful hash cracking with wordlist"""
        mock_validate.return_value = True
        mock_load.return_value = ['password', '123456']
        mock_wordlist.return_value = 'password'
        
        result = cracker.crack_hash('test_hash', Path('wordlist.txt'))
        
        assert result == 'password'
        mock_wordlist.assert_called_once()
        mock_patterns.assert_not_called()
        mock_brute.assert_not_called()
    
    @patch.object(AdvancedCracker, 'validate_hash')
    @patch.object(AdvancedCracker, 'load_wordlist')
    @patch.object(AdvancedCracker, '_try_wordlist')
    @patch.object(AdvancedCracker, '_try_patterns')
    @patch.object(AdvancedCracker, '_try_brute_force')
    def test_crack_hash_pattern_success(self, mock_brute, mock_patterns, mock_wordlist, mock_load, mock_validate, cracker):
        """Test successful hash cracking with patterns"""
        mock_validate.return_value = True
        mock_load.return_value = ['password', '123456']
        mock_wordlist.return_value = None
        mock_patterns.return_value = '20231225'
        
        result = cracker.crack_hash('test_hash', Path('wordlist.txt'))
        
        assert result == '20231225'
        mock_wordlist.assert_called_once()
        mock_patterns.assert_called_once()
        mock_brute.assert_not_called()
    
    @patch.object(AdvancedCracker, 'validate_hash')
    @patch.object(AdvancedCracker, 'load_wordlist')
    @patch.object(AdvancedCracker, '_try_wordlist')
    @patch.object(AdvancedCracker, '_try_patterns')
    @patch.object(AdvancedCracker, '_try_brute_force')
    def test_crack_hash_brute_force_success(self, mock_brute, mock_patterns, mock_wordlist, mock_load, mock_validate, cracker):
        """Test successful hash cracking with brute force"""
        mock_validate.return_value = True
        mock_load.return_value = ['password', '123456']
        mock_wordlist.return_value = None
        mock_patterns.return_value = None
        mock_brute.return_value = 'abc123'
        
        result = cracker.crack_hash('test_hash', Path('wordlist.txt'))
        
        assert result == 'abc123'
        mock_wordlist.assert_called_once()
        mock_patterns.assert_called_once()
        mock_brute.assert_called_once()
    
    @patch.object(AdvancedCracker, 'validate_hash')
    @patch.object(AdvancedCracker, 'load_wordlist')
    @patch.object(AdvancedCracker, '_try_wordlist')
    @patch.object(AdvancedCracker, '_try_patterns')
    @patch.object(AdvancedCracker, '_try_brute_force')
    def test_crack_hash_not_found(self, mock_brute, mock_patterns, mock_wordlist, mock_load, mock_validate, cracker):
        """Test hash cracking when password not found"""
        mock_validate.return_value = True
        mock_load.return_value = ['password', '123456']
        mock_wordlist.return_value = None
        mock_patterns.return_value = None
        mock_brute.return_value = None
        
        result = cracker.crack_hash('test_hash', Path('wordlist.txt'))
        
        assert result is None
    
    @patch.object(AdvancedCracker, 'check_password')
    @patch.object(AdvancedCracker, '_generate_variations')
    def test_try_wordlist(self, mock_variations, mock_check, cracker):
        """Test wordlist trying with variations"""
        passwords = ['password', 'admin']
        mock_check.side_effect = [False, False, False, True]  # Fourth check succeeds
        mock_variations.return_value = ['Password', 'PASSWORD']
        
        result = cracker._try_wordlist('test_hash', passwords)
        
        assert result == 'PASSWORD'
        assert mock_check.call_count == 4
        assert mock_variations.call_count == 2
    
    @patch.object(AdvancedCracker, 'check_password')
    def test_try_wordlist_with_stop_flag(self, mock_check, cracker):
        """Test wordlist trying with stop flag"""
        cracker.stop_flag.set()
        passwords = ['password']
        
        result = cracker._try_wordlist('test_hash', passwords)
        
        assert result is None
        mock_check.assert_not_called()
    
    def test_generate_variations(self, cracker):
        """Test password variation generation"""
        variations = cracker._generate_variations('password')
        
        assert isinstance(variations, list)
        assert 'password' in variations
        assert 'PASSWORD' in variations
        assert 'Password' in variations
        assert 'p@ssword' in variations
        assert 'passw0rd' in variations
        assert 'password123' in variations
        assert 'password!' in variations
    
    @patch.object(AdvancedCracker, 'check_password')
    def test_try_patterns_date_success(self, mock_check, cracker):
        """Test pattern trying with date pattern success"""
        mock_check.side_effect = lambda pwd, hash: pwd == '20231225'
        cracker.known_patterns['dates'] = {'20231225', '01012023'}
        
        result = cracker._try_patterns('test_hash')
        
        assert result == '20231225'
    
    @patch.object(AdvancedCracker, 'check_password')
    def test_try_patterns_keyboard_success(self, mock_check, cracker):
        """Test pattern trying with keyboard pattern success"""
        mock_check.return_value = False
        cracker.known_patterns['dates'] = set()
        cracker.known_patterns['keyboard_patterns'] = {'qwerty', 'asdf'}
        
        # Make keyboard pattern check succeed
        mock_check.side_effect = lambda pwd, hash: pwd == 'qwerty'
        
        result = cracker._try_patterns('test_hash')
        
        assert result == 'qwerty'
    
    @patch.object(AdvancedCracker, '_brute_force_length')
    def test_try_brute_force(self, mock_brute_length, cracker):
        """Test brute force trying"""
        mock_brute_length.side_effect = [None, None, 'found123', None]
        
        result = cracker._try_brute_force('test_hash')
        
        assert result == 'found123'
        assert mock_brute_length.call_count >= 3
    
    @patch('advanced_cracker.ThreadPoolExecutor')
    @patch.object(AdvancedCracker, '_brute_force_chunk')
    def test_brute_force_length(self, mock_chunk, mock_executor, cracker):
        """Test brute force with specific length"""
        # Mock the executor and futures
        mock_future = Mock(spec=Future)
        mock_future.result.return_value = 'abc123'
        mock_executor.return_value.__enter__.return_value.submit.return_value = mock_future
        
        result = cracker._brute_force_length('test_hash', 6, 'abcdef123')
        
        assert result == 'abc123'
    
    @patch.object(AdvancedCracker, 'check_password')
    def test_brute_force_chunk(self, mock_check, cracker):
        """Test brute force chunk processing"""
        mock_check.side_effect = [False, False, True]
        
        result = cracker._brute_force_chunk('test_hash', 3, 'ab', 'abc')
        
        assert result is not None
        assert len(result) == 3
    
    def test_analyze_password_strong(self, cracker):
        """Test password analysis for strong password"""
        analysis = cracker.analyze_password('P@ssw0rd123!')
        
        assert analysis['length'] == 12
        assert analysis['has_lowercase'] is True
        assert analysis['has_uppercase'] is True
        assert analysis['has_digits'] is True
        assert analysis['has_special'] is True
        assert analysis['strength_score'] >= 60
        assert analysis['strength_level'] in ['Strong', 'Very Strong']
    
    def test_analyze_password_weak(self, cracker):
        """Test password analysis for weak password"""
        cracker.known_patterns['common_words'] = {'password'}
        analysis = cracker.analyze_password('password')
        
        assert analysis['length'] == 8
        assert analysis['has_lowercase'] is True
        assert analysis['has_uppercase'] is False
        assert analysis['has_digits'] is False
        assert analysis['has_special'] is False
        assert analysis['is_common_word'] is True
        assert analysis['strength_score'] < 40
        assert analysis['strength_level'] in ['Weak', 'Very Weak']
    
    def test_analyze_password_with_patterns(self, cracker):
        """Test password analysis with patterns"""
        cracker.known_patterns['dates'] = {'20231225'}
        cracker.known_patterns['keyboard_patterns'] = {'qwerty'}
        
        # Test date pattern
        analysis = cracker.analyze_password('20231225')
        assert analysis['is_date_pattern'] is True
        
        # Test keyboard pattern
        analysis = cracker.analyze_password('qwerty')
        assert analysis['is_keyboard_pattern'] is True
    
    def test_get_strength_level(self, cracker):
        """Test strength level determination"""
        assert cracker._get_strength_level(85) == 'Very Strong'
        assert cracker._get_strength_level(70) == 'Strong'
        assert cracker._get_strength_level(50) == 'Moderate'
        assert cracker._get_strength_level(25) == 'Weak'
        assert cracker._get_strength_level(10) == 'Very Weak'


class TestMainFunction:
    """Test suite for main function"""
    
    @patch('sys.argv', ['advanced_cracker.py', 'analyze', '-t', 'P@ssw0rd123!'])
    @patch.object(AdvancedCracker, 'analyze_password')
    def test_main_analyze_mode(self, mock_analyze, capsys):
        """Test main function in analyze mode"""
        mock_analyze.return_value = {
            'length': 12,
            'entropy': 72.5,
            'has_lowercase': True,
            'has_uppercase': True,
            'has_digits': True,
            'has_special': True,
            'is_common_word': False,
            'is_date_pattern': False,
            'is_keyboard_pattern': False,
            'strength_score': 85,
            'strength_level': 'Very Strong'
        }
        
        main()
        
        captured = capsys.readouterr()
        assert "ADVANCED PASSWORD CRACKER v1.0" in captured.out
        assert "Analyzing password strength" in captured.out
        assert "Length: 12" in captured.out
        assert "Entropy: 72.50" in captured.out
        assert "Strength Level: Very Strong" in captured.out
    
    @patch('sys.argv', ['advanced_cracker.py', 'analyze'])
    def test_main_analyze_mode_no_password(self, capsys):
        """Test main function in analyze mode without password"""
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        
        captured = capsys.readouterr()
        assert "Please provide a password to analyze" in captured.out
    
    @patch('sys.argv', ['advanced_cracker.py', 'demo'])
    @patch.object(AdvancedCracker, 'analyze_password')
    def test_main_demo_mode(self, mock_analyze, capsys):
        """Test main function in demo mode"""
        mock_analyze.return_value = {
            'strength_level': 'Strong',
            'strength_score': 75
        }
        
        main()
        
        captured = capsys.readouterr()
        assert "Running demo mode" in captured.out
        assert "Demo: Analyzing password 'Password123!'" in captured.out
        assert "Strength Level: Strong" in captured.out
    
    @patch('sys.argv', ['advanced_cracker.py', 'crack', '-t', 'hash123'])
    @patch.object(AdvancedCracker, 'crack_hash')
    def test_main_crack_mode_success(self, mock_crack, capsys):
        """Test main function in crack mode with success"""
        mock_crack.return_value = 'foundpass'
        
        main()
        
        captured = capsys.readouterr()
        assert "Password found: foundpass" in captured.out
    
    @patch('sys.argv', ['advanced_cracker.py', 'crack', '-t', 'hash123'])
    @patch.object(AdvancedCracker, 'crack_hash')
    def test_main_crack_mode_failure(self, mock_crack, capsys):
        """Test main function in crack mode with failure"""
        mock_crack.return_value = None
        
        main()
        
        captured = capsys.readouterr()
        assert "Password not found using advanced techniques" in captured.out
    
    @patch('sys.argv', ['advanced_cracker.py', 'crack'])
    def test_main_crack_mode_no_input(self, capsys):
        """Test main function in crack mode without input"""
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        
        captured = capsys.readouterr()
        assert "Please provide a target hash" in captured.out