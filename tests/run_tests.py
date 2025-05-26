#!/usr/bin/env python3
"""
Test runner script for Password Cracker project
"""
import sys
import os
import argparse
import subprocess
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def run_tests(args):
    """Run tests based on provided arguments"""
    cmd = ['pytest']
    
    # Add verbosity
    if args.verbose:
        cmd.append('-vv')
    else:
        cmd.append('-v')
    
    # Add coverage if requested
    if args.coverage:
        cmd.extend(['--cov=.', '--cov-report=html', '--cov-report=term'])
    
    # Add specific test categories
    if args.unit:
        cmd.extend(['-m', 'unit'])
    elif args.integration:
        cmd.extend(['-m', 'integration'])
    elif args.security:
        cmd.extend(['-m', 'security'])
    elif args.performance:
        cmd.extend(['-m', 'performance'])
    elif args.smoke:
        cmd.extend(['-m', 'smoke'])
    
    # Add slow tests if requested
    if args.slow:
        cmd.append('--runslow')
    
    # Add specific test file if provided
    if args.file:
        cmd.append(args.file)
    
    # Add pytest-xdist for parallel execution
    if args.parallel:
        cmd.extend(['-n', str(args.parallel)])
    
    # Add failed first
    if args.failed_first:
        cmd.append('--failed-first')
    
    # Add last failed
    if args.last_failed:
        cmd.append('--last-failed')
    
    # Add stop on first failure
    if args.exitfirst:
        cmd.append('-x')
    
    # Add keyword expression
    if args.keyword:
        cmd.extend(['-k', args.keyword])
    
    # Add custom pytest args
    if args.pytest_args:
        cmd.extend(args.pytest_args.split())
    
    # Print command
    print(f"Running: {' '.join(cmd)}")
    print("-" * 80)
    
    # Run tests
    result = subprocess.run(cmd, cwd=Path(__file__).parent.parent)
    return result.returncode


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Run tests for Password Cracker project',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tests with coverage
  python run_tests.py --coverage
  
  # Run only unit tests
  python run_tests.py --unit
  
  # Run tests in parallel
  python run_tests.py --parallel 4
  
  # Run specific test file
  python run_tests.py --file tests/test_utils.py
  
  # Run tests matching keyword
  python run_tests.py -k "test_hash"
  
  # Run security tests with coverage
  python run_tests.py --security --coverage
        """
    )
    
    # Test selection arguments
    test_group = parser.add_argument_group('test selection')
    test_group.add_argument('--unit', action='store_true',
                           help='Run only unit tests')
    test_group.add_argument('--integration', action='store_true',
                           help='Run only integration tests')
    test_group.add_argument('--security', action='store_true',
                           help='Run only security tests')
    test_group.add_argument('--performance', action='store_true',
                           help='Run only performance tests')
    test_group.add_argument('--smoke', action='store_true',
                           help='Run only smoke tests')
    test_group.add_argument('--slow', action='store_true',
                           help='Include slow running tests')
    test_group.add_argument('-f', '--file', type=str,
                           help='Run specific test file')
    test_group.add_argument('-k', '--keyword', type=str,
                           help='Run tests matching keyword expression')
    
    # Execution arguments
    exec_group = parser.add_argument_group('execution options')
    exec_group.add_argument('-p', '--parallel', type=int, metavar='N',
                           help='Run tests in parallel using N workers')
    exec_group.add_argument('--failed-first', action='store_true',
                           help='Run failed tests first')
    exec_group.add_argument('--last-failed', action='store_true',
                           help='Run only last failed tests')
    exec_group.add_argument('-x', '--exitfirst', action='store_true',
                           help='Exit on first failure')
    
    # Output arguments
    output_group = parser.add_argument_group('output options')
    output_group.add_argument('-v', '--verbose', action='store_true',
                             help='Verbose output')
    output_group.add_argument('-c', '--coverage', action='store_true',
                             help='Generate coverage report')
    
    # Additional arguments
    parser.add_argument('--pytest-args', type=str,
                       help='Additional arguments to pass to pytest')
    
    args = parser.parse_args()
    
    # Run tests
    sys.exit(run_tests(args))


if __name__ == '__main__':
    main()