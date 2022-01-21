"""
KULeuven COSIC 
ProTego Access Control and Key Management framework
https://protego-project.eu/
Version 6.1
under a BSD license
"""
import sys
from Adata import Data_Analyser
from flask import Flask, request
import json
import jwt
import base64
import socket
from ast import literal_eval
import os
if "TOKEN_VERIFY" in os.environ and "PUBLIC_KEY" in os.environ:
    T_V = os.environ['TOKEN_VERIFY']
    P_K = os.environ['PUBLIC_KEY']
else:
    T_V = '0'
    P_K = 'not_public_key'
    
if "POLICY_RULE" in os.environ:
    P_F = os.environ['POLICY_RULE']#P_F was added to the policy file in this version
else:
    P_F = '0'
print("POLICY_RULE", P_F)#P_F was added to the policy file in this version    
print('TOKEN_VERIFY', T_V)
print('PUBLIC_KEY', P_K)

app = Flask(__name__)

error = {'status': "Error", 'errorMessage': "RevokedUser|NotAuthorized|MisformedToken|etc"}
def Token_val(E_D, token_Type, accessid_token, data, P_F, Group_IDs):#P_F was added to the policy file in this version
    try:
        decoded_f = jwt.decode(accessid_token, verify=False)        
        if token_Type == 'keycloak':
            #Pbkey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxA+bLf2Bg7TmcgWl4Lx3qRnNlttKM1KKB6QySqx95mnSYpf5m//ZWY6OQAfOctZnezU1RhcDe9JY8OjzqnEe8tdx5kqXSmmmGO82U2NNVLPb0l2Pg3EM9Ax/BqbVia6UBIkFh6miETBqLBm3zUXbRVs91blWnB/2x/pmRI6egfyy5NZl2rPmCKqdRjaKVSPQTs0RIpvUIY1W10T6a/aZI+pf0E9aK1RUx13PaZrQk0SGCST5xpMSDPVuYuvKUUKdf5lJ7f4EwYGgpnBpRH89xZGJ/LV0ipNiU7i5wf/pK5AA6bKMa6A2+gaIdfHJHU4D+LvWdjrI78tUcVCCeb40WQIDAQAB'
            Pbkey = P_K
            if E_D == 'e': flag = "00"
            elif E_D == 'd': flag = "01"

        elif token_Type == 'aws-cognito':
            #Pbkey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5HAb77vGkIlbd4WWZpbf2/nVAqJ7hFlznTSoP+1lprl5HsOUMOQMxvz3SzPyOvPiQC7SxO8UQO7c4eBNWpUJUhFZ3546PSHYFu+AmpjLHPHj/gp97l/7jlP5glyWPw6UnJ7iIca1ynBalTUWZ7w6ABz8lfqp4tUX3Mx6+e8GUOhPn8T+5ReDRxW12RIABj/yJ/3y6oCSKmYl12352MfmBbrrRTLCJvtMtcrbe0qCjtOVeUhJMOdlUb3pzl8g7C/MglnrKyMQM4HZVVwk3OLDuS3szLvZupSk7nXnsaAmNR/xaDnggiOdjIUi8CLbZBavAE58ixBLi7F8pwzteZL4/wIDAQAB'
            Pbkey = P_K
            if E_D == 'e': flag = "10"
            elif E_D == 'd': flag = "11"

        else:
            error.update(errorMessage='WrongTokenType')
            return error
        if T_V == '1':
            secretPEM = "-----BEGIN PUBLIC KEY-----\n" + Pbkey + "\n-----END PUBLIC KEY-----"
            decoded = jwt.decode(accessid_token, secretPEM, audience=decoded_f['aud'], algorithms=['RS256'])
        else:
            decoded = jwt.decode(accessid_token, verify=False)
        KEK_or_EKEK = Data_Analyser(data, flag, decoded, P_F, Group_IDs)#P_F was added to the policy file in this version
        print('sending data back to the client')
        return KEK_or_EKEK
    except jwt.ExpiredSignature:
        error.update(errorMessage='TokenHasExpired')
        return error
    except jwt.DecodeError:
        error.update(errorMessage='InvalidToken')
        return error
    except jwt.InvalidTokenError:
        error.update(errorMessage='InvalidToken')
        return error
@app.route('/KUL/KMS/encrypt', methods = ['POST'])
def determine_escalation1():
    E_D = 'e'
    jsondata = request.get_data()
    data = json.loads(jsondata)
    try:
        base64.b64decode(data['KEKorWrappedKEK'])
    except Exception:
        error.update(errorMessage='WrongDataFormat')
        return json.dumps(error)
    header = literal_eval(request.headers.get('Tokens'))
    if header['AuthToken'] == 's.JvKotVPg3HlQ1ZpchK6xerB':
        token_Type = header['tokenType']
        accessid_token = header['AccessOrIDToken']
        if 'Patient_IDs' in data:
            Group_IDs = (data['Patient_IDs'])
        else:
            print('No Patient_IDs!!!!!!!!!!!!!!')
            Group_IDs = {'Pid1': 'null'}
        return json.dumps(Token_val(E_D, token_Type, accessid_token, data, P_F, Group_IDs))#P_F was added to the policy file in this version
    else:
        error.update(errorMessage='UnAuthorizedDGW')
        return json.dumps(error)

@app.route('/KUL/KMS/decrypt', methods = ['POST'])
def determine_escalation2():
    E_D = 'd'
    jsondata = request.get_data()
    data = json.loads(jsondata)
    header = literal_eval(request.headers.get('Tokens'))
    if header['AuthToken'] == 's.JvKotVPg3HlQ1ZpchK6xerB':
        token_Type = header['tokenType']
        accessid_token = header['AccessOrIDToken']
        Group_IDs = 'No_Patient_IDs'
        return json.dumps(Token_val(E_D, token_Type, accessid_token, data, P_F, Group_IDs))#P_F was added to the policy file in this version
    else:
        error.update(errorMessage='UnAuthorizedDGW')
        return json.dumps(error)


if __name__ == '__main__':
    app.run(port=5000, host='0.0.0.0')
