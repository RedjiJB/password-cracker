"""
Integration tests for the Password Cracker web application
"""
import pytest
import json
import time
from pathlib import Path
from unittest.mock import patch, Mock

from web.app import app, analyze_password, generate_hash, crack_hash
from web.middleware import SecurityMiddleware


class TestWebIntegration:
    """Integration tests for web application"""
    
    @pytest.fixture
    def client(self):
        """Create a test client"""
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    
    @pytest.fixture
    def auth_headers(self):
        """Create authenticated headers"""
        return {
            'Content-Type': 'application/json',
            'X-API-Key': 'test-api-key'
        }
    
    def test_full_password_analysis_flow(self, client):
        """Test complete password analysis workflow"""
        # Test weak password
        response = client.post('/api/analyze',
                             json={'password': 'weak'},
                             content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['strength'] == 'Very Weak'
        assert data['score'] < 20
        
        # Test strong password
        response = client.post('/api/analyze',
                             json={'password': 'Str0ng!P@ssw0rd#2024'},
                             content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['strength'] in ['Strong', 'Very Strong']
        assert data['score'] >= 60
    
    def test_hash_generation_and_cracking_flow(self, client):
        """Test complete hash generation and cracking workflow"""
        # Generate hash
        password = 'testpassword123'
        response = client.post('/api/hash',
                             json={'password': password, 'algorithm': 'md5'},
                             content_type='application/json')
        assert response.status_code == 200
        hash_data = json.loads(response.data)
        generated_hash = hash_data['hash']
        
        # Try to crack the hash (should fail - not in demo database)
        response = client.post('/api/crack',
                             json={'hash': generated_hash, 'algorithm': 'md5'},
                             content_type='application/json')
        assert response.status_code == 200
        crack_data = json.loads(response.data)
        assert crack_data['found'] is False
        
        # Try with known demo hash
        response = client.post('/api/crack',
                             json={'hash': '5f4dcc3b5aa765d61d8327deb882cf99', 'algorithm': 'md5'},
                             content_type='application/json')
        assert response.status_code == 200
        crack_data = json.loads(response.data)
        assert crack_data['found'] is True
        assert crack_data['password'] == 'password'
    
    def test_multiple_algorithm_support(self, client):
        """Test support for multiple hash algorithms"""
        password = 'MultiAlgoTest123!'
        algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt']
        
        for algo in algorithms:
            response = client.post('/api/hash',
                                 json={'password': password, 'algorithm': algo},
                                 content_type='application/json')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['algorithm'] == algo
            assert 'hash' in data
            
            # Verify hash format
            if algo == 'bcrypt':
                assert data['hash'].startswith('$2b$')
            else:
                # Hex hash lengths
                expected_lengths = {
                    'md5': 32,
                    'sha1': 40,
                    'sha256': 64,
                    'sha512': 128
                }
                assert len(data['hash']) == expected_lengths[algo]
    
    def test_error_handling_integration(self, client):
        """Test error handling across endpoints"""
        # Empty password analysis
        response = client.post('/api/analyze',
                             json={'password': ''},
                             content_type='application/json')
        assert response.status_code == 400
        
        # Invalid algorithm
        response = client.post('/api/hash',
                             json={'password': 'test', 'algorithm': 'invalid'},
                             content_type='application/json')
        assert response.status_code == 400
        
        # Missing required fields
        response = client.post('/api/crack',
                             json={},
                             content_type='application/json')
        assert response.status_code == 400
    
    def test_concurrent_requests(self, client):
        """Test handling of concurrent requests"""
        import threading
        results = []
        
        def make_request(password):
            response = client.post('/api/analyze',
                                 json={'password': password},
                                 content_type='application/json')
            results.append(response.status_code)
        
        # Create multiple threads
        threads = []
        passwords = ['test1', 'test2', 'test3', 'test4', 'test5']
        
        for pwd in passwords:
            t = threading.Thread(target=make_request, args=(pwd,))
            threads.append(t)
            t.start()
        
        # Wait for all threads
        for t in threads:
            t.join()
        
        # All requests should succeed
        assert all(status == 200 for status in results)
        assert len(results) == len(passwords)
    
    def test_session_handling(self, client):
        """Test session handling across multiple requests"""
        # Make multiple requests in same session
        passwords = ['first', 'second', 'third']
        session_results = []
        
        with client.session_transaction() as sess:
            sess['test_id'] = 'test_session_123'
        
        for pwd in passwords:
            response = client.post('/api/analyze',
                                 json={'password': pwd},
                                 content_type='application/json')
            session_results.append(json.loads(response.data))
        
        # Verify all requests completed successfully
        assert len(session_results) == 3
        for result in session_results:
            assert 'score' in result
    
    def test_static_file_integration(self, client):
        """Test static file serving with main app"""
        # Request main page
        response = client.get('/')
        assert response.status_code == 200
        assert b'Password Cracker' in response.data
        
        # Request CSS file
        response = client.get('/static/css/style.css')
        assert response.status_code == 200
        assert 'text/css' in response.headers['Content-Type']
    
    def test_middleware_integration(self, client):
        """Test security middleware integration"""
        # Test security headers are applied
        response = client.get('/')
        assert 'X-Content-Type-Options' in response.headers
        assert 'X-Frame-Options' in response.headers
        
        # Test rate limiting integration
        # Make many requests quickly
        for i in range(105):
            response = client.get('/')
            if response.status_code == 429:
                break
        
        # Should hit rate limit
        assert response.status_code == 429
    
    def test_input_sanitization_integration(self, client):
        """Test input sanitization across endpoints"""
        # XSS attempt in password
        response = client.post('/api/analyze',
                             json={'password': '<script>alert("xss")</script>'},
                             content_type='application/json')
        assert response.status_code == 400
        
        # SQL injection attempt
        response = client.post('/api/analyze',
                             json={'password': "' OR '1'='1"},
                             content_type='application/json')
        assert response.status_code == 400
    
    def test_password_complexity_feedback(self, client):
        """Test password complexity analysis and feedback"""
        test_cases = [
            {
                'password': 'simple',
                'expected_feedback': ['Password should be at least 8 characters long']
            },
            {
                'password': 'onlylowercase',
                'expected_feedback': ['Add uppercase letters', 'Add numbers', 'Add special characters']
            },
            {
                'password': 'NoNumbers!',
                'expected_feedback': ['Add numbers']
            },
            {
                'password': 'P@ssw0rd123!',
                'expected_feedback': []
            }
        ]
        
        for test_case in test_cases:
            response = client.post('/api/analyze',
                                 json={'password': test_case['password']},
                                 content_type='application/json')
            assert response.status_code == 200
            data = json.loads(response.data)
            
            for expected in test_case['expected_feedback']:
                assert expected in data['feedback']
    
    @patch('web.app.bcrypt.gensalt')
    @patch('web.app.bcrypt.hashpw')
    def test_bcrypt_hash_generation(self, mock_hashpw, mock_gensalt, client):
        """Test bcrypt hash generation with mocked bcrypt"""
        mock_gensalt.return_value = b'$2b$12$salt'
        mock_hashpw.return_value = b'$2b$12$hashedpassword'
        
        response = client.post('/api/hash',
                             json={'password': 'testpass', 'algorithm': 'bcrypt'},
                             content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['algorithm'] == 'bcrypt'
        assert data['hash'] == '$2b$12$hashedpassword'
    
    def test_json_content_type_requirement(self, client):
        """Test that JSON content type is handled properly"""
        # Without content type
        response = client.post('/api/analyze',
                             data='{"password": "test"}')
        # Flask might still parse it, but good to test
        
        # With wrong content type
        response = client.post('/api/analyze',
                             data='password=test',
                             content_type='application/x-www-form-urlencoded')
        # Should either fail or return error
    
    def test_large_password_handling(self, client):
        """Test handling of large passwords"""
        # Test max length password (128 chars)
        large_password = 'A' * 128
        response = client.post('/api/analyze',
                             json={'password': large_password},
                             content_type='application/json')
        assert response.status_code == 200
        
        # Test over max length
        too_large = 'A' * 129
        response = client.post('/api/analyze',
                             json={'password': too_large},
                             content_type='application/json')
        # Should handle gracefully
    
    def test_unicode_password_handling(self, client):
        """Test handling of unicode characters in passwords"""
        unicode_passwords = [
            'café123',
            'пароль',
            '密码123',
            '🔒secure'
        ]
        
        for pwd in unicode_passwords:
            response = client.post('/api/analyze',
                                 json={'password': pwd},
                                 content_type='application/json')
            # Should handle unicode gracefully (either process or reject cleanly)
    
    def test_api_versioning_compatibility(self, client):
        """Test API compatibility and versioning"""
        # Test that endpoints respond as expected
        endpoints = [
            ('/api/analyze', 'POST', {'password': 'test'}),
            ('/api/hash', 'POST', {'password': 'test', 'algorithm': 'md5'}),
            ('/api/crack', 'POST', {'hash': 'testhash', 'algorithm': 'md5'})
        ]
        
        for endpoint, method, data in endpoints:
            if method == 'POST':
                response = client.post(endpoint, json=data, content_type='application/json')
                assert response.status_code in [200, 400]  # Either success or validation error
                assert response.content_type == 'application/json'