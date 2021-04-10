from setuptools import setup, find_packages

setup(
    name="aws-keLP",
    version="0.0.1",
    author="LamarrD",
    author_email="henry.773@osu.edu",
    description="Serverless IAM least privilege automation",
    entry_points={
        "console_scripts": ["kelp=kelp.__init__:main"],
    },
    include_package_data=True,
    install_requires=["boto3"],
    license="MIT",
    packages=find_packages(where="src"),
    package_data={"": ["*"]},
    package_dir={"": "src"},
    url="https://github.com/LamarrD/keLP",
    zip_safe=False,
)