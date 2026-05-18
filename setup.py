from setuptools import setup, find_packages

setup(
    name="mle_core",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "python-jose[cryptography]==3.5.0",
        "jwcrypto==1.5.7",
        "starlette>=0.22.0",
        "python-dotenv>=1.0.0"
    ],
)
