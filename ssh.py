import boto3

# aws ssm start-session --target $INSTANCE_ID \
#                        --document-name AWS-StartPortForwardingSession \
#                        --parameters '{"portNumber":["80"],"localPortNumber":["9999"]}'

client = boto3.client('ssm')

response = client.start_session(
    Target='string',
    DocumentName='string',
    Parameters={
        'string': [
            'string',
        ]
    }
)
