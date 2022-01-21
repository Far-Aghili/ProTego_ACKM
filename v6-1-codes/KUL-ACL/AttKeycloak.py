"""
KULeuven COSIC 
ProTego Access Control and Key Management framework
https://protego-project.eu/
Version 6.1
under a BSD licence
"""
import json

#this function is for keycloak token format, in this token we have both role and group
def Send_AttK(data, decoded):
    u_id = decoded['sub']
    roles = decoded['realm_access']
    roles_list = roles['roles']
    role = roles_list[0]# the first role only
    groups = decoded['groups']
    group = groups[0]
    u_att = {'u_role': role, 'u_group': group}
    u_MkId = (data['masterKeyId'])
    u_kek = (data['KEKorWrappedKEK'])
    return u_id, u_att, u_MkId, u_kek
