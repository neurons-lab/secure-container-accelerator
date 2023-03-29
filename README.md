# Container Accelerator

AWS CDK Example of Docker container deploy in AWS Infrastructure as Fargate Service.

## Pre-requirements

1. Have Docker service  installed and running.

2. Install AWS CDK.

    https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html

    ```bash
    npm install -g aws-cdk
    ```

3. Configure AWS credentials.

4. Bootstrap CDK if it is not bootstrapped.

    ```bash
    cdk bootstrap
    ```

## Deploy

1. Clone repository.

2. Install dependencies.

    ```bash
    pip install -r requirements.txt
    ```

3. Run deployment in `deploy` directory.

    ```bash
    cdk deploy
    ```

## Deploy Example

```bash
deploy> cdk deploy --require-approval never
✨  Synthesis time: 9.03s
ContainerAcceleratorStack: building assets...
...
ContainerAcceleratorStack: deploying... [1/1]
✨  Deployment time: 60.28s

Outputs:
ContainerAcceleratorStack.AppServiceUrl = Conta-AppSe-19HEDVTH7E208-717646561.us-east-1.elb.amazonaws.com

Stack ARN:
arn:aws:cloudformation:us-east-1:111111111111:stack/ContainerAcceleratorStack/cfb54bd0-ce64-11ed-8dcb-121b44e79a29
✨  Total time: 70.31s
```
