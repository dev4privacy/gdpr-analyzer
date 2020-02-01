# coding: utf-8

from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="gdpr_analyzer",
    version="0.1",
    author="dev4privacy",
    description="Measures the compliance of any web page with the GDPR by analyzing its source code and behaviour.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dev4privacy/gdpr-analyzer",
    install_requires=[
        "beautifulsoup4==4.8.2",
        "blessings==1.7",
        "bs4==0.0.1",
        "cairocffi==1.1.0",
        "CairoSVG==2.4.2",
        "certifi==2019.11.28",
        "cffi==1.13.2",
        "chardet==3.0.4",
        "cryptography==2.8",
        "cssselect2==0.2.2",
        "defusedxml==0.6.0",
        "html5lib==1.0.1",
        "idna==2.8",
        "Jinja2==2.10.3",
        "MarkupSafe==1.1.1",
        "mozfile==2.1.0",
        "mozlog==5.0",
        "mozprofile==2.4.0",
        "mozterm==1.0.0",
        "Pillow==7.0.0",
        "pycparser==2.19",
        "pyOpenSSL==19.1.0",
        "Pyphen==0.9.5",
        "requests==2.22.0",
        "selenium==3.141.0",
        "six==1.14.0",
        "soupsieve==1.9.5",
        "splinter==0.13.0",
        "tinycss==0.4",
        "tinycss2==1.0.2",
        "urllib3==1.25.7",
        "WeasyPrint==51"
    ],
    packages=find_packages(),
    package_data={
        "": ["*.ini"],
        "gdpr_analyzer.modules.report": ["images/*", "templates/*"]
    },
    entry_points={
        "console_scripts": ['gdpr-analyzer=gdpr_analyzer.__main__:main']
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPLv3 License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
