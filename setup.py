from setuptools import setup

setup(
    name="keLP",
    version="0.0.1",
    description="Serverless IAM least privilege automation",
    url="https://github.com/LamarrD/keLP",
    author="LamarrD",
    author_email="henry.773@osu.edu",
    license="MIT",
    packages=["kelp"],
    install_requires=["boto3"],
    zip_safe=False,
    package_data={"": ["*"]},
    include_package_data=True,
    entry_points={
        "console_scripts": ["kelp=kelp.__init__:main"],
    },
)