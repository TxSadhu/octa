from setuptools import setup, find_packages

setup(
    name="octa",
    version="0.0.1",
    author="Suman Basuli",
    author_email="thinisadhu@gmail.com",
    packages=find_packages(),
    include_package_data=True,
    url="http://pypi.python.org/pypi/domfu/",
    license="LICENSE.txt",
    description="A magical port scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    install_requires=[
        "click",
        "yaspin",
        "requests",
        "requests[socks]",
        "requests[security]",
        "scapy",
    ],
    entry_points="""
        [console_scripts]
        octa=octa.__main__:scan
    """,
)
