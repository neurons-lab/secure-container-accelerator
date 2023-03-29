"""AWS CDK Deploy Script"""
from constructs import Construct
from aws_cdk import (
    App,
    Stack,
    CfnOutput,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_ecr_assets as ecr_assets,
)


# Stack
class AppStack(Stack):
    """
    Sample Docker App Deployment Stack
    Contians:
    - VPC
    - DockerImage
    - Fargate Cluster
    - Fargate Service App
    """
    def __init__(self, scope: Construct, _id: str, **kwargs) -> None:
        """Init"""
        super().__init__(scope, _id, **kwargs)

        # VPC
        vpc = ec2.Vpc(
            self, 'AppVpc',
            ip_addresses=ec2.IpAddresses.cidr('10.0.0.0/16'),
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name='public',
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                )
            ])

        # App Image
        image = ecr_assets.DockerImageAsset(
            self, 'AppImage',
            directory='../app')

        # # Fargate Application
        cluster = ecs.Cluster(self, 'AppCluster', vpc=vpc)
        service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self, 'AppService',
            cluster=cluster,
            cpu=256,
            memory_limit_mib=512,
            desired_count=1,
            assign_public_ip=True,
            public_load_balancer=True,
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_docker_image_asset(image),
            ))
        CfnOutput(
            self, 'AppServiceUrl', description='App Service URL',
            export_name='appServiceUrl', value=service.load_balancer.load_balancer_dns_name)


# App
app = App()

# Stack
AppStack(app, f'ContainerAcceleratorStack')

# Synth
app.synth()
