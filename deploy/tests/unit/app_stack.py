import os
import aws_cdk as core
import aws_cdk.assertions as assertions

from stack.app_stack import AppStack

# example tests. To run these tests, uncomment this file along with the example
# resource in test_stack/test_stack_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AppStack(app, 'AppStack', env=core.Environment(
        account=os.getenv('AWS_ACCOUNT_ID', os.getenv('CDK_DEFAULT_ACCOUNT')),
        region=os.getenv('AWS_DEFAULT_REGION', os.getenv('CDK_DEFAULT_REGION'))
    ))
    template = assertions.Template.from_stack(stack)

    # template.has_resource_properties('AWS::SQS::Queue', {
    #     'VisibilityTimeout': 300
    # })
