from setuptools import setup

from http_tunnel import __version__

setup(
    name='http-tunnel',
    version=__version__,
    description='HTTP tunneling tool.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='yxc890123',
    url='https://github.com/yxc890123/http-tunnel',
    packages=['http_tunnel'],
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3'
    ],
    license='Apache 2.0',
    include_package_data=True,
    python_requires='>=3.8',
    install_requires=[
        'requests[socks]',
        'fastapi-slim',
        'uvicorn',
        'websockets',
        'cryptography'
    ],
    entry_points={
        'console_scripts': ['http-tunnel = http_tunnel.cli:main']
    }
)
