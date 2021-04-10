import json
import gzip
import sys
import os
import subprocess
import logging
import argparse

import boto3

# import localstack_client.session as boto3
from time import sleep, time


logger = logging.getLogger(__name__)


# Colors - https://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
# Success - https://gist.github.com/hit9/5635505
class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    grey = "\x1b[2m"
    white = "\x1b[38;21m"
    green = "\x1b[32;1m"
    yellow = "\x1b[33;1m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format = "keLP - {funcName} - {message}"

    logging.SUCCESS = 25  # between WARNING and INFO
    logging.addLevelName(logging.SUCCESS, "SUCCESS")

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: white + format + reset,
        logging.SUCCESS: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: bold_red + format + reset,
        logging.CRITICAL: red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, style="{")
        return formatter.format(record)


def deploy_application(args):
    """Run a sls deploy ton deploy the severless application"""
    logger.info("Deploying application...")
    logger.info(f"Checking in {args.path} for IAC files")
    os.chdir(args.path)

    if args.debug:
        result = subprocess.run(["sls", "deploy", "--stage=prod", "-v"])
    else:
        result = subprocess.run(["sls", "deploy", "--stage=prod"], stdout=subprocess.DEVNULL)

    if result.returncode != 0:
        logger.exception("Failed to deploy application")
        sys.exit()
    os.chdir("..")
    logger.info("Application deployed successfully")


def deploy_trail():
    """Create s3 bucket and cloudtrail via cfn"""
    my_dir = os.path.dirname(__file__)
    logger.info("Creating cloudtrail and accompanying logging bucket...")
    client = boto3.client("cloudformation", region_name="us-east-1")
    cfn_template_body = open(os.path.join(my_dir, "bucket.yml")).read()
    response = client.create_stack(
        StackName="kelp-bucket-stack",
        TemplateBody=cfn_template_body,
    )

    # Wait for bucket stack to finish deploying to deploy trail
    response = client.describe_stacks(StackName="kelp-bucket-stack")
    while response["Stacks"][0]["StackStatus"] == "CREATE_IN_PROGRESS":
        sleep(2)
        response = client.describe_stacks(StackName="kelp-bucket-stack")

    cfn_template_body = open(os.path.join(my_dir, "trail.yml")).read()
    response = client.create_stack(
        StackName="kelp-trail-stack",
        TemplateBody=cfn_template_body,
    )

    # Wait for trail to deploy to finish
    response = client.describe_stacks(StackName="kelp-trail-stack")
    while response["Stacks"][0]["StackStatus"] == "CREATE_IN_PROGRESS":
        sleep(2)
        response = client.describe_stacks(StackName="kelp-trail-stack")

    logger.info("Cloudtrail deployed successfully")
    # NOTE - Cloudtrail weird, give it a sec to settle
    sleep(3)


def get_functions(args):
    """Read lambda function definitions from IAC"""
    functions = {}
    iac_file = f"{args.path}/.serverless/serverless-state.json"
    logger.info(f"Reading lambdas and permissions from {iac_file}...")
    iac_file_data = json.load(open(iac_file))

    for lambda_function in iac_file_data["service"]["functions"].values():
        role = lambda_function["role"]
        statements = ""
        for lambda_policies in iac_file_data["service"]["resources"]["Resources"][role][
            "Properties"
        ]["Policies"]:
            for statement in lambda_policies["PolicyDocument"]["Statement"]:
                # TODO need to Evaluate Intrinsic functions for resources if they need it
                statements = statement

        functions[lambda_function["name"]] = {
            "name": lambda_function["name"],
            "policy": statements,
            "lp_policy": [],
        }
    logger.info(f"Found lambdas: {','.join(list(functions.keys()))}")
    return functions


def invoke_functions(functions):
    """Invoke lambda functions so logs get captured by cloudtrail"""
    for function in functions:
        client = boto3.client("lambda", region_name="us-east-1")
        logger.info(f"Invoking {function}")
        response = client.invoke(
            FunctionName=function, InvocationType="RequestResponse", LogType="Tail"
        )
        if response["StatusCode"] != 200:
            logger.exception("Lambda failed to execute")
            sys.exit()


def get_used_permissions(functions):
    """Check cloudtrail logs to see what permissions the lambdas used"""
    logger.info("Checking for cloudtrail logs...")
    s3 = boto3.resource("s3")
    bucket = s3.Bucket("kelp-bucket-logging")
    lambdas = set()
    client = boto3.client("sts")
    account_id = client.get_caller_identity()["Account"]

    objs = list(bucket.objects.filter(Prefix=f"AWSLogs/{account_id}/CloudTrail/us-east-1"))
    timeout_start = time()
    while len(objs) == 0:
        sleep(3)
        objs = list(bucket.objects.filter(Prefix=f"AWSLogs/{account_id}/CloudTrail/us-east-1"))

        # If it's been over 60 seconds try invoking the functions again
        if time() - timeout_start > 60:
            logger.info("Cloudtrail timeout")
            invoke_functions(functions)
            logger.info("Checking for cloudtrail logs...")
            timeout_start = time()

    log_files = [log_file.key for log_file in bucket.objects.all() if ".gz" in log_file.key]
    logger.info(f"Log Files Found: {len(log_files)}")
    logger.debug(log_files)
    logger.info("Downloading log files")

    s3 = boto3.client("s3")
    for log_file in log_files:
        filename = f"test{time()}.gz"
        s3.download_file("kelp-bucket-logging", log_file, filename)
        f = gzip.open(filename, "rb")
        file_content = f.read()
        data = json.loads(file_content)
        f.close()

        for record in data["Records"]:
            if "principalId" not in record["userIdentity"].keys():
                continue
            principal_id = record["userIdentity"]["principalId"].split(":")[-1]
            if principal_id in functions.keys():
                lambdas.add(principal_id)
                service = record["eventSource"].split(".")[0]
                lp_iam_role = {
                    "Effect": "Allow",
                    "Action": [f"{service}:{record['eventName']}"],
                    "Resource": [resource["ARN"] for resource in record["resources"]],
                }
                functions[principal_id]["lp_policy"] = lp_iam_role
    if set(functions.keys()) != lambdas:
        logger.warning("Log file didn't contain all lambda invocations")
        logger.debug(f"{set(functions.keys())} != {lambdas}")
        invoke_functions(functions)
        sleep(60)
        get_used_permissions(functions)

    return functions


def compare_permissions(functions):
    """Compare permissions provisioned vs permissions used"""
    logger.info("Comparing permissions requested vs used")
    logger.debug(functions)
    lp = True
    for function in functions.values():
        logger.info(f"Checking {function['name']}")
        # Get and potentially fix policy
        policy = function["policy"]
        lp_policy = function["lp_policy"]
        if type(policy["Resource"]) == list:
            policy["Resource"] = policy["Resource"][0]
        if type(lp_policy["Resource"]) == list:
            lp_policy["Resource"] = lp_policy["Resource"][0]

        # Check Effect, Action, and Resources
        if policy["Effect"] != lp_policy["Effect"]:
            logger.info(f"  Effect {policy['Effect']} != {lp_policy['Effect']}")
            lp = False
        if policy["Action"] != lp_policy["Action"]:
            logger.info(f"  Action {policy['Action']} != {lp_policy['Action']}")
            lp = False
        if policy["Resource"] != lp_policy["Resource"]:
            logger.info(f"  Resource: {policy['Resource']} != {lp_policy['Resource']}")
            lp = False
        if lp:
            logger.success(f"Lambda {function['name']} has a least privileged IAM role ✓")
            continue

        logger.error(f"Lambda {function['name']} doesn't have a least privileged IAM role")
        logger.error(f"The role was: {json.dumps(policy,indent=2)}")
        logger.success(f"The role should be: {json.dumps(lp_policy,indent=2)}")


def cleanup(args):
    """Remove resources created, s3 bucket, cloudtrail, stacks"""
    logger.info("Cleaning up all AWS resources used")
    s3_client = boto3.client("s3", region_name="us-east-1")
    s3 = boto3.resource("s3")

    # Cleanup logging bucket
    if s3.Bucket("kelp-bucket-logging") in s3.buckets.all():
        logger.info("Deleting logging bucket...")
        bucket = s3.Bucket("kelp-bucket-logging")
        bucket.objects.all().delete()
        response = s3_client.delete_bucket(Bucket="kelp-bucket-logging")

    # Cleanup cfn stacks for trail and accompanying logging bucket
    client = boto3.client("cloudformation", region_name="us-east-1")
    response = client.list_stacks(
        StackStatusFilter=[
            "ROLLBACK_COMPLETE",
            "CREATE_COMPLETE",
            "UPDATE_COMPLETE",
            "UPDATE_ROLLBACK_COMPLETE",
            "DELETE_FAILED",
        ]
    )
    if "kelp-bucket-stack" in [stack["StackName"] for stack in response["StackSummaries"]]:
        logger.info("Deleting logging bucket stack...")
        client.delete_stack(StackName="kelp-bucket-stack")
    if "kelp-trail-stack" in [stack["StackName"] for stack in response["StackSummaries"]]:
        logger.info("Deleting cloudtrail stack...")
        client.delete_stack(StackName="kelp-trail-stack")

    # Destroy application
    # NOTE - when this is in localstack I won't need to worry about this
    if s3.Bucket("kelp-bucket") in s3.buckets.all():
        logger.info("Deleting application bucket...")
        bucket = s3.Bucket("kelp-bucket")
        bucket.objects.all().delete()

    os.chdir(args.path)
    if args.debug:
        result = subprocess.run(["sls", "remove", "--stage=prod"])
    else:
        result = subprocess.run(["sls", "remove", "--stage=prod"], stdout=subprocess.DEVNULL)
    if result.returncode != 0:
        logger.exception("Failed to remove application from AWS")
        sys.exit()
    os.chdir("..")

    # Remove local files created
    files_in_directory = os.listdir(".")
    filtered_files = [file for file in files_in_directory if file.endswith(".gz")]
    for file in filtered_files:
        os.remove(file)

    print("Cleanup successful")


def setup():
    """Setup CLI Arguments and logger"""
    description = "Determine if serverless application is using least-privilege IAM roles."
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-v", "--verbose", help="see detailed output", action="store_true")
    parser.add_argument("-d", "--debug", help="see debugging output", action="store_true")
    parser.add_argument("-p", "--path", help="path to folder containing IAC", default="iac")
    args = parser.parse_args()

    # Setup Logger
    ch = logging.StreamHandler()
    ch.setFormatter(CustomFormatter())
    setattr(logger, "success", lambda message, *args: logger._log(logging.SUCCESS, message, args))
    logger.setLevel(logging.SUCCESS)
    logger.success("Starting")

    if args.debug:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)

    logger.addHandler(ch)
    return args


def main():
    args = setup()
    try:
        deploy_application(args)
        deploy_trail()
        functions = get_functions(args)
        invoke_functions(functions)
        functions = get_used_permissions(functions)
        compare_permissions(functions)
    except Exception as e:
        logger.error(e, exc_info=True)
    finally:
        cleanup(args)


if __name__ == "__main__":
    main()