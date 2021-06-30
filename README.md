# hcqis_vipaccess

Uses vipaccess for automatic STS credential grabbing/role assumption. The STS session information is written to /.aws/credentials.

https://github.com/dlenski/python-vipaccess/blob/master/README.md


# /.aws/hcqis_creds.txt

This file needs four lines:
<aws_account_number>
<role_to_assume>
<hcqis_AD>@qnet.qualnet.org
<hcqis AD password>

