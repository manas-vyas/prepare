Powershell script

# Parameters
$UserNames = @("demo", "test")  # Replace with the IAM user names to rotate keys for
$SecretName = "mytest"                # Replace with the name of the secret in Secrets Manager

# Initialize an empty hashtable to store all keys
$SecretData = @{}

foreach ($UserName in $UserNames) {
    Write-Output "Processing user: $UserName"

    # Step 1: List Access Keys and delete the older one if there are two
    $AccessKeys = aws iam list-access-keys --user-name $UserName | ConvertFrom-Json

    if ($AccessKeys.AccessKeyMetadata.Count -ge 1) {
        # Delete all existing access keys for the user
        foreach ($Key in $AccessKeys.AccessKeyMetadata) {
            aws iam delete-access-key --user-name $UserName --access-key-id $Key.AccessKeyId
            Write-Output "Deleted old access key: $($Key.AccessKeyId) for user: $UserName"
        }
    }

    # Step 2: Create a new Access Key
    $NewAccessKey = aws iam create-access-key --user-name $UserName | ConvertFrom-Json
    $AccessKeyId = $NewAccessKey.AccessKey.AccessKeyId
    $SecretAccessKey = $NewAccessKey.AccessKey.SecretAccessKey

    # Step 3: Add new key to the hashtable with username as part of the key
    # Ensure keys are non-null and structured correctly
    $SecretData["${UserName}_AccessKeyId"] = "$AccessKeyId"
    $SecretData["${UserName}_SecretAccessKey"] = "$SecretAccessKey"

    Write-Output "New Access Key created for user: $UserName"
}
Write-Output $SecretData

# Step 4: Convert hashtable to JSON and update Secrets Manager
$SecretValue = $SecretData | ConvertTo-Json -Compress

Write-Output $SecretValue


$EscapedSecretValue = $SecretValue -replace '"', '\"'
aws secretsmanager put-secret-value --secret-id $SecretName --secret-string "$EscapedSecretValue"

# Output confirmation (optional)
Write-Output "All access keys updated in Secrets Manager for $SecretName"

==========================================================================================================
Lambda Function

import json
import boto3

def lambda_handler(event, context):
    # Initialize clients
    iam_client = boto3.client('iam')
    secretsmanager_client = boto3.client('secretsmanager')
    
    # Hardcoded user names and secret name
    user_names = ["demo", "test"]  # List of IAM user names
    secret_name = "mytest"          # Name of the secret in Secrets Manager

    secret_data = {}
    
    for user_name in user_names:
        print(f"Processing user: {user_name}")

        # Step 1: List Access Keys
        try:
            response = iam_client.list_access_keys(UserName=user_name)
            access_keys = response['AccessKeyMetadata']
        except Exception as e:
            print(f"Error listing access keys for {user_name}: {e}")
            continue
        
        # Step 2: Delete existing keys
        for key in access_keys:
            try:
                iam_client.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])
                print(f"Deleted old access key: {key['AccessKeyId']} for user: {user_name}")
            except Exception as e:
                print(f"Error deleting access key {key['AccessKeyId']} for {user_name}: {e}")

        # Step 3: Create a new Access Key
        try:
            new_key = iam_client.create_access_key(UserName=user_name)
            access_key_id = new_key['AccessKey']['AccessKeyId']
            secret_access_key = new_key['AccessKey']['SecretAccessKey']

            # Step 4: Store new keys in the dictionary
            secret_data[f"{user_name}_AccessKeyId"] = access_key_id
            secret_data[f"{user_name}_SecretAccessKey"] = secret_access_key
            
            print(f"New Access Key created for user: {user_name}")
        except Exception as e:
            print(f"Error creating access key for {user_name}: {e}")

    # Step 5: Update Secrets Manager
    try:
        secret_value = json.dumps(secret_data)
        secretsmanager_client.put_secret_value(SecretId=secret_name, SecretString=secret_value)
        print(f"All access keys updated in Secrets Manager for {secret_name}")
    except Exception as e:
        print(f"Error updating Secrets Manager: {e}")
    
    return {
        'statusCode': 200,
        'body': json.dumps('Access keys rotated successfully!')
    }

===================================================================================

import boto3
import os

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')
    codepipeline = boto3.client('codepipeline')
    
    instance_id = 'i-0018d1f66a0be698f'  # Replace with your instance ID
    pipeline_name = os.environ.get('PIPELINE_NAME') or event.get('pipeline_name')
    
    # Fetch the latest pipeline execution ID
    try:
        # List pipeline executions for the given pipeline
        response = codepipeline.list_pipeline_executions(
            pipelineName=pipeline_name,
            maxResults=1  # Only fetch the latest execution
        )
        
        # Get the latest pipeline execution ID (if available)
        pipeline_execution_id = None
        if 'pipelineExecutionSummaries' in response and len(response['pipelineExecutionSummaries']) > 0:
            pipeline_execution_id = response['pipelineExecutionSummaries'][0]['pipelineExecutionId']
        
        if not pipeline_execution_id:
            raise Exception(f"Could not find the latest pipeline execution ID for pipeline: {pipeline_name}")
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': f"Error fetching pipeline execution ID: {str(e)}"
        }

    # Get the instance status
    try:
        response = ec2.describe_instance_status(InstanceIds=[instance_id])
        statuses = response.get('InstanceStatuses', [])
        
        # Check if instance is running
        if statuses and statuses[0]['InstanceState']['Name'] == 'running':
            return {
                'statusCode': 200,
                'body': 'Server is up and running.'
            }
        else:
            # Stop the pipeline execution if the server is not running
            codepipeline.stop_pipeline_execution(
                pipelineName=pipeline_name,
                pipelineExecutionId=pipeline_execution_id,
                reason=f"EC2 instance {instance_id} is not running. Stopping pipeline."
            )
            
            # Raise exception to stop the pipeline
            raise Exception("Server is not ready for deployment")
    
    except Exception as e:
        return {
            'statusCode': 500,
            'body': f"Error checking instance status or stopping pipeline: {str(e)}"
        }




