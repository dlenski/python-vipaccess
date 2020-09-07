from setuptools import setup
from io import open

with open('description.rst', encoding='utf-8') as f:
    description = f.read()

setup(
    name='python-vipaccess',
    version='0.13',
    description="A free software implementation of Symantec's VIP Access application and protocol",
    long_description=description,
    url='https://github.com/dlenski/python-vipaccess',
    author='Daniel Lenski',
    author_email='dlenski@gmail.com',
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 4 - Beta',
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
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='development',
    packages=['vipaccess'],
    install_requires=[
        # verify consistency with requirements.txt
        'pycryptodome>=3.6.6',
        'oath>=1.4.1',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'vipaccess=vipaccess.__main__:main',
        ],
    },
    test_requires=[
        'nose>=1.0',
    ],
    test_suite='nose.collector',
)
