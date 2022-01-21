"""
KULeuven COSIC 
ProTego Access Control and Key Management framework
https://protego-project.eu/
Version 6.1
under a BSD license
"""

______reads rego file from the host c:\protego1/acl and copy that to the /home/KUL-ACL_____
POLICY_FILE=0 ===> like before
POLICY_FILE=1 ===> OPA
******it also supports Token verification*******

docker image build -t code/kulacc:v6.1 .

docker run -idt -e POLICY_RULE=1 -v c:\protego1/acl:/var -e TOKEN_VERIFY=1 -e PUBLIC_KEY=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6S7asUuzq5Q/3U9rbs+PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb/XqZaKgSYaC/h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB+etoNdL3Ir2746KIy/VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtwIDAQAB -p 6611:5000 --name v6_1_code code/kulacc:v6.1
docker run -idt -e POLICY_RULE=1 -v c:\protego1/acl:/var -p 6661:5000 --name v6_1code code/kulacc:v6.1


