"""
KULeuven COSIC 
ProTego Access Control and Key Management framework
https://protego-project.eu/
Version 5
under a BSD license
"""

# The access control function

def Receive_decision(u_id, id, u_group, Grp, u_role, Rl):

    print("these are access control policies")

    if u_group[1:-1] == '/Doctors' or u_group[1:-1] == 'doctor':
        acc='full'
    else:
        acc='part'
    print(acc)

    rules = [u_id == id,
             u_group == Grp,
             u_role == Rl]

    print(rules)

# The decision  point

    if acc == 'full' or all(rules):
        R_decision = '1'
    else:
        R_decision = '0'

    return R_decision
