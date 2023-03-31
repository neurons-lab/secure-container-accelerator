import os
import aws_cdk as core
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks
from stack.app_stack import AppStack
import pytest
import unittest
import aws_cdk.assertions as assertions
import logging as log
from dotenv import load_dotenv
load_dotenv('.env.sample', override=False)
load_dotenv('.env', override=True)


class TestNug(unittest.TestCase):

    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)

    def test_nug(self):
        """Test the AppStack"""
        app = core.App()
        core.Aspects.of(app).add(HIPAASecurityChecks(verbose=True, reports=True))
        core.Aspects.of(app).add(AwsSolutionsChecks(verbose=True, reports=True))
        stack = AppStack(app, 'AppStack', env=core.Environment(
            account=os.getenv('AWS_ACCOUNT_ID', os.getenv('CDK_DEFAULT_ACCOUNT')),
            region=os.getenv('AWS_DEFAULT_REGION', os.getenv('CDK_DEFAULT_REGION'))
        ))

        hippa_warnings = assertions.Annotations.from_stack(stack).find_warning(
            "*", assertions.Match.string_like_regexp("HIPAA.Security-.*")
        )
        for warning in hippa_warnings:
            log.error(warning.entry.data)
        aws_warnings = assertions.Annotations.from_stack(stack).find_warning(
            "*", assertions.Match.string_like_regexp("AwsSolutions-.*")
        )
        for warning in aws_warnings:
            log.error(warning.entry.data)

        assert not hippa_warnings
        assert not aws_warnings
