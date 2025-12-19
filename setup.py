from setuptools import setup, find_packages

setup(
    name="parambuster",
    version="7.0.0",
    author="ArkhAngelLifeJiggy",
    description="Advanced High-Performance Parameter Detection and Vulnerability Scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/LifeJiggy/ParamBuster",
    packages=find_packages(),
    py_modules=["ParamBuster"],
    install_requires=[
        "requests",
        "beautifulsoup4",
        "fake-useragent",
        "urllib3",
        "colorama",
        "selenium",
        "webdriver-manager",
    ],
    entry_points={
        "console_scripts": [
            "parambuster=ParamBuster:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
)
