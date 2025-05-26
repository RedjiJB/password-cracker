"""
Performance tests for the Password Cracker application
"""
import pytest
import time
import hashlib
import statistics
from pathlib import Path
from unittest.mock import patch, Mock
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import cProfile
import pstats
import io

from base_cracker import BaseCracker
from basic_cracker import BasicCracker
from advanced_cracker import AdvancedCracker
from utils import hash_password, verify_password, calculate_entropy
from config import MAX_THREADS, RATE_LIMIT


class TestCrackerPerformance:
    """Performance tests for password cracking operations"""
    
    @pytest.fixture
    def wordlist(self, tmp_path):
        """Create a test wordlist with various sizes"""
        small_list = tmp_path / "small_wordlist.txt"
        medium_list = tmp_path / "medium_wordlist.txt"
        large_list = tmp_path / "large_wordlist.txt"
        
        # Small: 100 passwords
        small_list.write_text('\n'.join([f'password{i}' for i in range(100)]))
        
        # Medium: 1,000 passwords
        medium_list.write_text('\n'.join([f'password{i}' for i in range(1000)]))
        
        # Large: 10,000 passwords
        large_list.write_text('\n'.join([f'password{i}' for i in range(10000)]))
        
        return {
            'small': small_list,
            'medium': medium_list,
            'large': large_list
        }
    
    @pytest.mark.performance
    def test_basic_cracker_speed(self, wordlist):
        """Test basic cracker performance with different wordlist sizes"""
        cracker = BasicCracker('sha256')
        target_hash = hashlib.sha256(b'password500').hexdigest()
        
        results = {}
        
        for size, path in wordlist.items():
            start = time.perf_counter()
            result = cracker.crack_hash(target_hash, path)
            elapsed = time.perf_counter() - start
            
            results[size] = {
                'time': elapsed,
                'found': result is not None,
                'attempts_per_second': cracker.attempts / elapsed if elapsed > 0 else 0
            }
            
            cracker.cleanup()
        
        # Performance assertions
        assert results['small']['time'] < 1.0  # Should complete in under 1 second
        assert results['medium']['time'] < 5.0  # Should complete in under 5 seconds
        assert results['large']['time'] < 30.0  # Should complete in under 30 seconds
        
        # Should maintain reasonable throughput
        for size in results:
            assert results[size]['attempts_per_second'] > 100  # At least 100 attempts/sec
    
    @pytest.mark.performance
    def test_advanced_cracker_multithreading(self):
        """Test advanced cracker multithreading performance"""
        cracker = AdvancedCracker('sha256')
        
        # Test thread scaling
        thread_counts = [1, 2, 4, 8]
        results = {}
        
        for thread_count in thread_counts:
            with patch('advanced_cracker.MAX_THREADS', thread_count):
                start = time.perf_counter()
                
                # Simulate brute force work
                cracker._brute_force_length(
                    'dummy_hash',
                    6,
                    'abcdefghijklmnopqrstuvwxyz0123456789'
                )
                
                elapsed = time.perf_counter() - start
                results[thread_count] = elapsed
        
        # Should show improvement with more threads (up to a point)
        # 2 threads should be faster than 1
        assert results[2] < results[1] * 0.9  # At least 10% improvement
        
        # But diminishing returns after optimal thread count
        # 8 threads might not be much better than 4
    
    @pytest.mark.performance
    def test_hash_algorithm_performance(self):
        """Compare performance of different hash algorithms"""
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        password = 'testpassword123'
        iterations = 10000
        
        results = {}
        
        for algo in algorithms:
            start = time.perf_counter()
            
            for _ in range(iterations):
                hash_password(password, algo)
            
            elapsed = time.perf_counter() - start
            results[algo] = {
                'total_time': elapsed,
                'hashes_per_second': iterations / elapsed
            }
        
        # MD5 should be fastest (but insecure)
        assert results['md5']['hashes_per_second'] > results['sha256']['hashes_per_second']
        
        # SHA-512 should be slowest
        assert results['sha512']['hashes_per_second'] < results['sha256']['hashes_per_second']
        
        # All should achieve reasonable throughput
        for algo in algorithms:
            assert results[algo]['hashes_per_second'] > 1000  # At least 1000 hashes/sec
    
    @pytest.mark.performance
    def test_bcrypt_performance(self):
        """Test bcrypt performance with different cost factors"""
        password = 'testpassword123'
        
        # Test different cost factors
        cost_factors = [4, 8, 10, 12]
        results = {}
        
        for cost in cost_factors:
            with patch('bcrypt.gensalt') as mock_gensalt:
                mock_gensalt.return_value = f'$2b${cost:02d}${"a"*22}'.encode()
                
                start = time.perf_counter()
                hash_password(password, 'bcrypt')
                elapsed = time.perf_counter() - start
                
                results[cost] = elapsed
        
        # Higher cost factors should take longer
        assert results[12] > results[10]
        assert results[10] > results[8]
        assert results[8] > results[4]
        
        # But all should complete in reasonable time
        assert all(t < 1.0 for t in results.values())  # Under 1 second each
    
    @pytest.mark.performance
    def test_memory_usage(self, wordlist):
        """Test memory usage doesn't grow excessively"""
        import tracemalloc
        
        tracemalloc.start()
        
        cracker = BasicCracker('sha256')
        
        # Get initial memory usage
        initial_memory = tracemalloc.get_traced_memory()[0]
        
        # Process large wordlist
        target_hash = hashlib.sha256(b'notfound').hexdigest()
        cracker.crack_hash(target_hash, wordlist['large'])
        
        # Get peak memory usage
        peak_memory = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        
        memory_increase = (peak_memory - initial_memory) / 1024 / 1024  # MB
        
        # Should not use excessive memory (less than 100MB for 10k passwords)
        assert memory_increase < 100
    
    @pytest.mark.performance
    def test_rate_limiting_performance(self):
        """Test rate limiting doesn't excessively impact performance"""
        cracker = BasicCracker('sha256')
        
        # Time operations with rate limiting
        start = time.perf_counter()
        successful_attempts = 0
        
        for i in range(100):
            try:
                if cracker.check_password(f'test{i}', 'dummy_hash'):
                    successful_attempts += 1
            except:
                pass
        
        elapsed = time.perf_counter() - start
        
        # Should achieve close to configured rate limit
        actual_rate = successful_attempts / elapsed
        expected_rate = RATE_LIMIT
        
        # Allow 20% variance
        assert actual_rate > expected_rate * 0.8
        assert actual_rate < expected_rate * 1.2
    
    @pytest.mark.performance
    def test_concurrent_request_performance(self):
        """Test performance under concurrent load"""
        from web.app import app
        
        app.config['TESTING'] = True
        client = app.test_client()
        
        # Test concurrent requests
        num_requests = 100
        num_threads = 10
        
        results = []
        errors = []
        
        def make_request():
            try:
                start = time.perf_counter()
                response = client.post('/api/analyze',
                                     json={'password': 'test123'},
                                     content_type='application/json')
                elapsed = time.perf_counter() - start
                results.append(elapsed)
                return response.status_code == 200
            except Exception as e:
                errors.append(str(e))
                return False
        
        # Execute requests concurrently
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(make_request) for _ in range(num_requests)]
            success_count = sum(1 for f in futures if f.result())
        
        # Calculate statistics
        if results:
            avg_response_time = statistics.mean(results)
            p95_response_time = statistics.quantiles(results, n=20)[18]  # 95th percentile
            
            # Performance assertions
            assert success_count >= num_requests * 0.95  # At least 95% success rate
            assert avg_response_time < 0.1  # Average under 100ms
            assert p95_response_time < 0.5  # 95th percentile under 500ms
            assert len(errors) < num_requests * 0.05  # Less than 5% errors
    
    @pytest.mark.performance
    def test_entropy_calculation_performance(self):
        """Test entropy calculation performance"""
        passwords = [
            'a' * 8,
            'password123',
            'P@ssw0rd!',
            'ThisIsAVeryLongPasswordWithManyDifferentCharacterTypes123!@#',
            '🔒SecurityTest123!',  # Unicode
        ]
        
        iterations = 1000
        
        for password in passwords:
            start = time.perf_counter()
            
            for _ in range(iterations):
                calculate_entropy(password)
            
            elapsed = time.perf_counter() - start
            calculations_per_second = iterations / elapsed
            
            # Should handle at least 10,000 calculations per second
            assert calculations_per_second > 10000
    
    @pytest.mark.performance
    def test_pattern_generation_performance(self):
        """Test pattern generation performance in advanced cracker"""
        cracker = AdvancedCracker('sha256')
        
        # Time pattern generation
        start = time.perf_counter()
        date_patterns = cracker._generate_date_patterns()
        date_time = time.perf_counter() - start
        
        start = time.perf_counter()
        keyboard_patterns = cracker._generate_keyboard_patterns()
        keyboard_time = time.perf_counter() - start
        
        # Should generate patterns quickly
        assert date_time < 5.0  # Under 5 seconds for date patterns
        assert keyboard_time < 0.1  # Under 100ms for keyboard patterns
        
        # Should generate reasonable number of patterns
        assert 1000 < len(date_patterns) < 1000000  # Reasonable range
        assert 10 < len(keyboard_patterns) < 1000  # Reasonable range
    
    @pytest.mark.performance
    def test_profiling_basic_cracker(self, wordlist, tmp_path):
        """Profile basic cracker to identify bottlenecks"""
        cracker = BasicCracker('sha256')
        target_hash = hashlib.sha256(b'password999').hexdigest()
        
        # Profile the crack operation
        profiler = cProfile.Profile()
        profiler.enable()
        
        result = cracker.crack_hash(target_hash, wordlist['medium'])
        
        profiler.disable()
        
        # Analyze profile results
        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
        ps.print_stats(10)  # Top 10 functions
        
        profile_output = s.getvalue()
        
        # Save profile for analysis
        profile_file = tmp_path / "profile_results.txt"
        profile_file.write_text(profile_output)
        
        # Basic assertions about performance
        assert result == 'password999'
        assert cracker.attempts == 1000  # Should have tried all passwords
    
    @pytest.mark.performance
    @pytest.mark.slow
    def test_stress_test_large_scale(self, tmp_path):
        """Stress test with very large wordlist"""
        # Create a very large wordlist (100k passwords)
        huge_list = tmp_path / "huge_wordlist.txt"
        
        # Generate in chunks to avoid memory issues
        with open(huge_list, 'w') as f:
            for i in range(100000):
                f.write(f'password{i}\n')
        
        cracker = BasicCracker('md5')  # Use MD5 for speed in stress test
        target_hash = hashlib.md5(b'password99999').hexdigest()
        
        start = time.perf_counter()
        result = cracker.crack_hash(target_hash, huge_list)
        elapsed = time.perf_counter() - start
        
        # Should complete even with large wordlist
        assert result == 'password99999'
        assert elapsed < 60  # Under 1 minute
        
        # Calculate throughput
        throughput = cracker.attempts / elapsed
        assert throughput > 1000  # At least 1000 passwords/second