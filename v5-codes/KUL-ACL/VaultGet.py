"""
KULeuven COSIC 
ProTego Access Control and Key Management framework
https://protego-project.eu/
Version 5
under a BSD license
"""
import json
import os
import base64
from AclPolicy import Receive_decision

def Receive_Vault(u_id, u_att, u_MkId, u_kek):
    u_role = json.dumps(u_att['u_role'])# dict to data serialized
    u_group = json.dumps(u_att['u_group'])# dict to data serialized
    edata = {
        "ciphertext": "%s" %u_kek
    }
    with open("edata_file.json", "w") as write_efile:
        json.dump(edata, write_efile)
        write_efile.close()
    with open('/home/keys.txt') as f:
        for line in f:
            if "Initial Root Token:" in line:
                R_token = line.rsplit(None, 1)[-1]
    os.system('curl --header "X-Vault-Token: %s" --request POST --data @edata_file.json http://127.0.0.1:8200/v1/transit/decrypt/%s>detext.txt'%(R_token, u_MkId))
    with open('detext.txt') as djson_file:
        Ddata = json.load(djson_file)
        p_text = Ddata['data']
        print(p_text['plaintext'])
        djson_file.close()
    x_KEK=base64.b64decode(p_text['plaintext']).decode('utf-8')
    print(x_KEK)
    p_dot2 = x_KEK.find('...')
    KEK = x_KEK[p_dot2 + 3:len(x_KEK)]
    p_dot1 = x_KEK.find('..')
    Grp = x_KEK[p_dot1 + 2:p_dot2]
    p_dot0 = x_KEK.find('.')
    Rl = x_KEK[p_dot0 + 1:p_dot1]
    id = x_KEK[:p_dot0]
    print(u_id, id, u_group, Grp, u_role, Rl)
    KEK_decision = Receive_decision(u_id, id, u_group, Grp, u_role, Rl)
    if KEK_decision == '1':
        R_KEK = {'status': "OK", 'unwrappedKey': "%s" % KEK}
    else:
        R_KEK = {'status': "Error", 'errorMessage': "NotAuthorized User"}

    return R_KEK
