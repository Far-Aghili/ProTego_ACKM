"""
KULeuven COSIC 
ProTego Access Control and Key Management framework
https://protego-project.eu/
Version 6.1
under a BSD license
"""
#Analyze  the received data and return the result back
import sys
import json
from AttKeycloak import Send_AttK
from AttCognito import Send_AttC
from VaultPut import Send_Vault
from VaultGet import Receive_Vault


def Data_Analyser(data, u_flag, decoded, P_F, Group_IDs):
    try:
        if u_flag == '00' or u_flag == '01':#keycloak
            u_id, u_att, u_MkId, u_kek = Send_AttK(data, decoded)
        elif u_flag == '10' or u_flag == '11':#aws cognito
            u_id, u_att, u_MkId, u_kek = Send_AttC(data, decoded)
            #
        if u_flag == '00' or u_flag == '10':#wrapping
            KEK_kek = Send_Vault(u_id, u_att, u_MkId, u_kek, Group_IDs)#Group_IDs was added to the policy file
            KEK_or_EKEK = KEK_kek
        elif u_flag == '01' or u_flag == '11':#unwrapping
            KEK = Receive_Vault(u_id, u_att, u_MkId, u_kek, P_F)#P_F was added to the policy file
            KEK_or_EKEK = KEK
        return KEK_or_EKEK
    except Exception:
        error = {'status': "Error", 'errorMessage': "MisformedMessage"}
        return error
