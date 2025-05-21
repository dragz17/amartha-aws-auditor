from setuptools import setup, find_packages

setup(
    name="aws-auditor",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "boto3",
        "uvicorn",
        "PyYAML",
        "requests",
        "secure-smtplib",
        "pytest",
        "pytest-cov",
        "bandit",
        "safety"
    ],
    python_requires=">=3.10",
)
