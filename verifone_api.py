import csv
from multiprocessing import Pool

from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Cipher import PKCS1_v1_5

import requests
import xmltodict, json

url = "https://txn-cst.cxmlpg.com/XML4/commideagateway.asmx"

headers = {
    'Accept-Encoding': 'gzip,deflate',
    'Content-Type': 'application/soap+xml;charset=UTF-8;action="https://www.commidea.webservices.com/ProcessMsg"',
    'Host': 'txn-test.cxmlpg.com',
    'Connection': 'Keep-Alive',
    'User-Agent': 'Apache-HttpClient/4.5.2 (Java/1.8.0_102)'
}


def inner(token):
    payload = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:com=\"https://www.commidea.webservices.com\">\n   <soap:Header/>\n   <soap:Body>\n      <com:ProcessMsg>\n         <com:Message>\n            <com:ClientHeader>\n               <com:SystemID>30002411</com:SystemID>\n               <com:SystemGUID>096d5d0f-f9dc-430a-8d9c-e102393409c4</com:SystemGUID>\n               <com:Passcode>17075320</com:Passcode>\n               <com:SendAttempt>0</com:SendAttempt>\n               <com:CDATAWrapping>false</com:CDATAWrapping>\n            </com:ClientHeader>\n            <com:MsgType>DETOKENREQUEST</com:MsgType><com:MsgData>&lt;?xml version=\"1.0\"?>&lt;detokenrequest xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"DETOKEN\">&lt;tokenid>" + token + "&lt;/tokenid>&lt;/detokenrequest></com:MsgData>\n         </com:Message>\n      </com:ProcessMsg>\n   </soap:Body>\n</soap:Envelope>"

    response = requests.request("POST", url, headers=headers, data=payload)
    y = json.loads(json.dumps(xmltodict.parse(response.text.encode('utf8'))))
    message = (y["soap:Envelope"]["soap:Body"]["ProcessMsgResponse"]["ProcessMsgResult"]["MsgData"])
    result = json.loads(json.dumps(xmltodict.parse(message)))

    # results
    errorcode = result["detokenresponse"]["errorcode"]
    if errorcode != "0":
        print("No value for token {}".format(token))
        errors_writer.writerow([token, errorcode])
    else:
        keyname = result["detokenresponse"]["keyname"]
        pan = result["detokenresponse"]["pan"]
        cardschemeid = result["detokenresponse"]["cardschemeid"]
        cardschemename = result["detokenresponse"]["cardschemename"]
        expirydate = result["detokenresponse"]["expirydate"]
        tokenexpirationdate = result["detokenresponse"]["tokenexpirationdate"]

        raw_cipher_data = b64decode(pan)
        phn = cipher.decrypt(raw_cipher_data, '')
        # print(phn.decode('Ascii'))

        res = [token, cardschemename, phn.decode('Ascii'), expirydate]
        # print("Saving token {}".format(token))
        # csvwriter.writerow(res)
        return res


# http://commaquote.azurewebsites.net/
my_list = ['10470898801',
           '10470898501',
           '10470888901',
           '10470845501',
           '10470781401',
           '10000009701']
columns = ['Token', 'CardschemeName', 'PAN', 'ExpirationDate']
f = open("path-to-results.csv", "w+")
csvwriter = csv.writer(f)
csvwriter.writerow(columns)

errors_file = open("path-to-failed_tokens.csv", "w+")
error_columns = ['Token', 'ErrorCode']
errors_writer = csv.writer(errors_file)
errors_writer.writerow(error_columns)

rsa_key = RSA.importKey(open("path-to-omni2.pem", "rb").read())
cipher = PKCS1_v1_5.new(rsa_key)


def mp_worker(next_token):
    try:
        return inner(next_token)
    except Exception as e:
        print("Exception happened for token {}".format(next_token))


def mp_handler():
    p = Pool() #input number of processes here
    with open("path-to-results.csv", "w+") as f:
        for result in p.imap(mp_worker, my_list):
            csvwriter.writerow(result)

if __name__ == '__main__':
    mp_handler()


