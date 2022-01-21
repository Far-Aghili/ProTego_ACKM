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

def Send_Vault(u_id, u_att, u_MkId, u_kek):
    u_role = json.dumps(u_att['u_role'])# dict to data serialized
    u_group = json.dumps(u_att['u_group'])# dict to data serialized
    u_Ptext = u_id + '.' + u_role + '.' + '.' + u_group + '.'+ '.' + '.' + u_kek
    encodedBytes = base64.b64encode(u_Ptext.encode("utf-8"))
    data = {
        "plaintext": "%s" % encodedBytes.decode('utf-8')
    }
    with open("data_file.json", "w") as write_file:
        json.dump(data, write_file)
        write_file.close()
    with open('/home/keys.txt') as f:
        for line in f:
            if "Initial Root Token:" in line:
                R_token = line.rsplit(None, 1)[-1]
        # ***now the master id and the key strings are ready to put to the vault____save the ciphertext on entext.text to extract the version
    os.system('curl --header "X-Vault-Token: %s" --request POST --data @data_file.json http://127.0.0.1:8200/v1/transit/encrypt/%s>entext.txt'%(R_token, u_MkId))
    with open('entext.txt') as ejson_file:
        Edata = json.load(ejson_file)
        ejson_file.close()
    EKEK = {'status': "OK"}
    EKEK.update(Edata['data'])
    return EKEK
