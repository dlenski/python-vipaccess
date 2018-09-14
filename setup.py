from setuptools import setup
from io import open

with open('README.md', encoding='utf-8') as f:
    readme = f.read()

setup(
    name='python-vipaccess',
    version='0.3.1',
    description="A free software implementation of Symantec's VIP Access application and protocol",
    long_description=readme,
    url='https://github.com/cyrozap/python-vipaccess',
    author='Forest Crossman',
    author_email='cyrozap@gmail.com',
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='development',
    packages=['vipaccess'],
    install_requires=[
        'lxml',
        'oath',
        'pycryptodome',
        'requests',
        'oath',
    ],
    entry_points={
        'console_scripts': [
            'vipaccess=vipaccess.cli:main',
        ],
    },
    test_suite='nose.collector',
)
