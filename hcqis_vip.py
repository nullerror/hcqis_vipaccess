import requests
import re
import boto3
from botocore.config import Config
from pathlib import Path
import configparser
import os

sts_url = 'https://sts.qualnet.org/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'
home = str(Path.home())
configloc = home + "/.aws/credentials"
config_profile = 'default'
def getCreds():
    try:
        creds = [line.rstrip() for line in open(home + '/.aws/hcqis_creds.txt')]
        return [x for x in creds]
    except:
        print("{}/.aws/hcqis_creds.txt not found! Please create it as follows: \
        \n\nLine 1: AWS Account number \
        \nLine 2: Role to Assume \
        \nLine 3: HCQIS AD Username (with @qnet.qualnet.org) \
        \nLine 4: AD Password \
        \n\nExample: \
        \n123456789101 \
        \nADFS-SOME-ROLE-ADMIN \
        \nusername@qnet.qualnet.org \
        \nsupersecretpassword".format(home))
        exit(1)

def qualnetAuth(username,password,sts_url):
    payload = {}
    payload['UserName'] = username
    payload['Password'] = password
    session = requests.Session()    # New Session Object
    formresponse = session.get(sts_url)    # Build a session at sts_url
    login_response = session.post(sts_url, data=payload)    # Post the Login
    get_context = 'Context\" value=\"(.*?)\"'    # Grab 'context' field value from the auth page response
    payload['context'] = re.search(get_context, login_response.text)[1]    # Set it in the payload...
    client_request_id = re.search("&client-request-id=(.*)\">",login_response.text) # client_id to pass this with VIP post request
    return client_request_id, payload, session


def getVIP(client_request_id, payload, session):
    try:
        payload['security_code'] = os.popen('vipaccess').read().rstrip()
    except:
        print("vipaccess binary not found. To enable automatic filling of vip token, please see https://github.com/dlenski/python-vipaccess/blob/master/README.md for instructions.")
        payload['security_code'] = input("VIP Code: ")
    vip_response = session.post(sts_url + "&client-request-id=" + client_request_id[1] , data=payload) # Send the VIP code to the login page, and grab the response
    return vip_response


def configSTS(vip_response, role,acct):
    get_saml = 'SAMLResponse\" value=\"(.*?)\"'
    saml_response = re.search(get_saml,vip_response.text)[1] # The response is just a SAML token, and grab it.
    role_arn = 'arn:aws:iam::{}:role/{}'.format(acct, role)
    principal_arn = 'arn:aws:iam::{}:saml-provider/HCQIS-ADFS'.format(acct)
    get_token = boto3.client('sts',config=Config(region_name='us-east-1'))
    token = get_token.assume_role_with_saml(
    PrincipalArn=principal_arn,
    RoleArn=role_arn,
    SAMLAssertion=saml_response,
    DurationSeconds=(3600))
    return token

def writeConfig(token):
    config = configparser.ConfigParser()# Create config object
    config.read(configloc)# Read config file into it (so it doesn't overwrite)
    aws_creds = {'region': 'us-east-1', 'aws_access_key_id': token['Credentials']['AccessKeyId'],
                          'aws_secret_access_key': token['Credentials']['SecretAccessKey'],
                          'aws_session_token': token['Credentials']['SessionToken']}
    if not config.has_section(config_profile):
        config.add_section(config_profile)
    for k,v in aws_creds.items():
        config.set(config_profile, k,v)
    with open(configloc, 'w') as configfile:
      config.write(configfile)
    print("Credentials added to {}/.aws/credentials. They are good for 1 hour.".format(home))



def main():
    acct, role, username, password = getCreds()
    client_request_id, payload, session = qualnetAuth(username,password,sts_url)
    vip_response = getVIP(client_request_id, payload, session)
    aws_creds = configSTS(vip_response, role,acct)
    writeConfig(aws_creds)

if __name__ == '__main__':
    main()
