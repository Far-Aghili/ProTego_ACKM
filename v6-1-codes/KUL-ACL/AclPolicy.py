"""
KULeuven COSIC 
ProTego Access Control and Key Management framework
https://protego-project.eu/
Version 6.1
under a BSD license
"""
import json
import itertools
import os
import shutil

def Receive_decision(u_id, id, u_group, Grp, u_role, Rl, P_F, Group_IDs):
    R_decision = '0'
    EHR_id_value = u_id
    vault_id_value = json.loads(Group_IDs)
    dcc=''
    for j in vault_id_value:
        jj = vault_id_value[str(j)]
        d = '"Pid": "%s"'%jj
        dcc+=','+ '{'+d+ '}'
    doct = '['+dcc[1:]+ ']'
    users = json.loads(doct)
#############################Generating Inputs File <<<<OPA>>>>
    input_data = {
        "user": u_id,
        "role": u_group[1:-1],
        "action": "read",
        "point": 1000,
        "u_i": users,
        "u_a": {u_id: {"tenure": 5, "dp_id": id, "dp_role": Grp[1:-1]}},
        "f_a": {
            "type": {"t1": "photo", "t2": 4},
            "version": {"v1": "1", "v2": 2}
        }
    }

    with open("input_opa.json", "w") as write_file:
        json.dump(input_data, write_file)
#############################Start Default Polices
    if u_group[1:-1] == '/Doctors' or u_group[1:-1] == 'doctor':
        acc='full'
    else:
        acc='part'
    print(acc)

    rules = [u_id == id,
             u_group == Grp,
             u_role == Rl]
    print(rules)
    print('Rule_No.: ', P_F)
##############################Default Rule <<<<TP>>>>
    if P_F == '0':
        if acc == 'full' and u_id == id:
            R_decision = '1'
        elif acc == 'full' and Grp[1:-1] == '/patient':
            R_decision = '1'
        elif acc == 'full' and Grp[1:-1] == 'patient':
            R_decision = '1'
        elif all(rules):
            R_decision = '1'
        elif EHR_id_value in vault_id_value.values():
            R_decision = '1'
        else:
            R_decision = '0'
        print('D', R_decision)
        return R_decision
##############################External Rule <<<<OPA>>>>+TP
    else:
        if all(rules):
            R_decision = '1'
            print('decision is from fast TPA: D=', R_decision)
            return R_decision
        shutil.copy('/var/abac1.rego', '/home/KUL-ACL/abac1.rego')
        os.system('./opa eval -i input_opa.json -d abac1.rego "data.abac1.allow">opaout.txt')
        with open('opaout.txt') as djson_file:
            opadata = json.load(djson_file)
            djson_file.close()
            print(opadata)
            opa_out = opadata['result'][0]['expressions'][0]['value']
            print('OPA_output', opa_out)
            if opa_out:
                R_decision = '1'
        print('D', R_decision)
        return R_decision
