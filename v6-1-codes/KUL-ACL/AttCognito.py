"""
KULeuven COSIC 
ProTego Access Control and Key Management framework
https://protego-project.eu/
Version 6.1
under a BSD license
"""
import json

#this function is for aws-cognito token format, in this token we have both role and group
def Send_AttC(data, decoded):
    u_id = decoded['sub']
    role = decoded['custom:rol']
    group = decoded['custom:rol']
    u_att = {'u_role': role, 'u_group': group}
    u_MkId = (data['masterKeyId'])
    u_kek = (data['KEKorWrappedKEK'])
    return u_id, u_att, u_MkId, u_kek
