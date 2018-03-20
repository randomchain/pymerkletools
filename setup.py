import os

from setuptools import setup, find_packages

setup_requirements = [
    'setuptools_scm',
]

setup(
    name='merkletools',
    use_scm_version=True,
    description='Merkle Tools',
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    url='https://github.com/randomchain/pymerkletools',
    author='Eder Santana',
    keywords='merkle tree, blockchain, tierion',
    license="MIT",
    packages=find_packages(),
    include_package_data=False,
    zip_safe=False,
    setup_requires=setup_requirements,
)
