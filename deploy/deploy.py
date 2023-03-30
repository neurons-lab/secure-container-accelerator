"""AWS CDK Deploy Script"""
import os
from constructs import Construct
from aws_cdk import (
    App,
    Environment,
    Stack,
    Duration,
    CfnOutput,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_ecr_assets as ecr_assets,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    aws_certificatemanager as acm,
)
from dotenv import load_dotenv
load_dotenv()


# Stack
class AppStack(Stack):
    """
    Sample Docker App Deployment Stack
    Require:
    - Pre-created HostedZone
    - ZONE_NAME
    - DOMAIN_NAME
    Contians:
    - VPC
    - DockerImage
    - Fargate Cluster
    - Fargate Service App
    """
    def __init__(self, scope: Construct, _id: str, **kwargs) -> None:
        """Init"""
        super().__init__(scope, _id, **kwargs)

        # Env
        zone_name = os.environ.get('ZONE_NAME', 'example.com')
        domain_name = os.environ.get('DOMAIN_NAME', 'app.example.com')

        # Hosted Zone
        hosted_zone = route53.HostedZone.from_lookup(
            self, 'HostedZone', domain_name=zone_name)

        # Cert
        cert = acm.Certificate(
            self, 'AppCert',
            domain_name=domain_name,
            validation=acm.CertificateValidation.from_dns(hosted_zone))

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

        # Docker Image
        image = ecr_assets.DockerImageAsset(
            self, 'AppImage', directory='../app')

        # Fargate Application
        cluster = ecs.Cluster(self, 'AppCluster', vpc=vpc)
        service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self, 'AppService',
            cluster=cluster,
            cpu=256,
            memory_limit_mib=512,
            desired_count=1,
            assign_public_ip=True,
            public_load_balancer=True,
            certificate=cert,
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_docker_image_asset(image),
            ))
        CfnOutput(
            self, 'AppServiceAlbUrl', description='App Service ALB URL',
            export_name='appServiceAlbUrl', value=service.load_balancer.load_balancer_dns_name)

        # Domain
        domain = route53.ARecord(
            self, 'AppDomain',
            zone=hosted_zone,
            record_name=domain_name,
            target=route53.RecordTarget.from_alias(
                route53_targets.LoadBalancerTarget(service.load_balancer)),
            ttl=Duration.seconds(60))
        CfnOutput(
            self, 'AppServiceUrl', description='App Service URL',
            export_name='appServiceUrl', value=domain.domain_name)


# App
app = App()

# Stack
AppStack(
    app, 'ContainerAcceleratorStack',
    env=Environment(
        account=os.environ["CDK_DEFAULT_ACCOUNT"],
        region=os.environ["CDK_DEFAULT_REGION"]))

# Synth
app.synth()
