from setuptools import setup, find_packages

setup(
    name="cloudpilot",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={"cloudpilot": ["dashboard/static/**/*"]},
    install_requires=[
        "boto3>=1.28.0",
        "rich>=13.0.0",
        "click>=8.0.0",
        "requests>=2.28.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "bedrock-agentcore>=1.4.0",
        "mcp>=1.0.0",
    ],
    extras_require={
        "test": [
            "pytest>=7.0",
            "hypothesis>=6.0",
            "httpx>=0.24",
            "pytest-asyncio>=0.21",
        ],
    },
    entry_points={"console_scripts": ["cloudpilot=cloudpilot.cli:cli"]},
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
)
