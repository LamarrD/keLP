import json
import boto3
import os


def lambda_handler(event, context):
    """ Lambda that uploads a file to an s3 bucket """
    bucket_name = os.environ.get("bucket")
    encoded_string = "Hi peeps".encode("utf-8")
    file_name = "test.txt"
    # s3 = boto3.resource("s3", verify=False)
    s3 = boto3.resource("s3")
    s3.Bucket(bucket_name).put_object(Key=file_name, Body=encoded_string)
    return {"statusCode": 200, "body": json.dumps("Hello from Lambda!")}


if __name__ == "__main__":
    lambda_handler("a", "b ")
