from setuptools import setup, find_packages

requires = [
    'awscli>=1.17.5,<2.0',
    'botocore>=1.14.5,<2.0',
]
test_requirements = [
    'mock>=3.0',
]

setup(
    name='aws-simple-mfa',
    version='0.3',
    packages=find_packages(exclude=['tests*']),
    description='Simple MFA plugin for AWS CLI',
    author='kenshin54',
    author_email='i@kenshin54.me',
    url='https://github.com/kenshin54/aws-simple-mfa',
    keywords=['awscli', 'plugin', 'mfa'],
    install_requires=requires,
    tests_require=test_requirements,
)
