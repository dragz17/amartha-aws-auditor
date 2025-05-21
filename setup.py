from setuptools import setup, find_packages

setup(
    name="amartha-aws-auditor",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3",
        "fastapi",
        "requests",
        "pyyaml",
    ],
    python_requires=">=3.10",
) 