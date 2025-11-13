"""Setup script for CyAudit Opus v3.4"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / 'README.md'
long_description = readme_file.read_text(encoding='utf-8') if readme_file.exists() else ''

setup(
    name='cyaudit-opus',
    version='3.4',
    description='Comprehensive Windows Security Assessment Tool with Splunk Integration',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='SignalFI',
    author_email='support@signalfi.com',
    url='https://github.com/signalfi/cyaudit_windows',
    packages=find_packages(),
    python_requires='>=3.7',
    install_requires=[
        # Uses only Python standard library
    ],
    entry_points={
        'console_scripts': [
            'cyaudit=cyaudit:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: Microsoft :: Windows',
    ],
    keywords='security audit windows splunk assessment compliance',
    project_urls={
        'Bug Reports': 'https://github.com/signalfi/cyaudit_windows/issues',
        'Source': 'https://github.com/signalfi/cyaudit_windows',
    },
)
