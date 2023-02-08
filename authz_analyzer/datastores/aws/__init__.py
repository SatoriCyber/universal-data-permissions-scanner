import os
import sys

# !Temporary solution!
# Until we will create a dedicated repo for the aws_ptrp_package (we don't want to put this package as sibling to authz_analyzer package)
# We want to emphasize that the aws_ptrp_package (AWS Principal to Resource Permissions) is actually a python package and not a inner module in authz_analyzer package
# By adding the below sys, we can work with all internal modules of aws_ptrp as actual separated package
# Both mypy, pylint has valid solution for this workaround (check the .pylintrc, mypy.ini)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "aws_ptrp_package"))
