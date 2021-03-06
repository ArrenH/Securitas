from distutils.core import setup
from setuptools import find_packages

setup(
    name = 'securitas',
    packages = find_packages(),
    include_package_data=True,
    version = 'v1.0.1',  # Ideally should be same as your github release tag varsion
    description = 'Python SDK to increase productivity and ease implementation of Symantec Validation and ID Protection (VIP) which is a two factor authentication API',
    author = 'Allen Huynh, Gabriel Morcote, Hanlin Ye',
    author_email = '',
    install_requires= ['suds_jurko'],
    url = 'https://github.com/ArrenH/Securitas',
    download_url = 'https://github.com/ArrenH/Securitas/archive/v1.0.tar.gz',
    keywords = ['Symantec', 'VIP', 'Python', 'SOAP', 'Validation and Identity Protection', '2FA', 'two factor authentication'],
    classifiers = [],
)
