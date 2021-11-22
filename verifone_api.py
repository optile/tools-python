import csv
from multiprocessing import Pool

from Crypto.PublicKey import RSA
from base64 import b64decode
from Crypto.Cipher import PKCS1_v1_5

import requests
import xmltodict, json

url = "https://txn-cst.cxmlpg.com/XML4/commideagateway.asmx" #sandbox URL

#url = "https://PAYMENT.cxmlpg.com/XML4/commideagateway.asmx" #live URL

headers = {
    'Accept-Encoding': 'gzip,deflate',
    'Content-Type': 'application/soap+xml;charset=UTF-8;action="https://www.commidea.webservices.com/ProcessMsg"',
    'Host': 'txn-test.cxmlpg.com',
    'Connection': 'Keep-Alive',
    'User-Agent': 'Apache-HttpClient/4.5.2 (Java/1.8.0_102)'
}

with open("failed_tokens.csv", "w+") as errors_file:
    error_columns = ['Token', 'ErrorCode']
    errors_writer = csv.writer(errors_file)
    errors_writer.writerow(error_columns)

def inner(token):
    # insert credentials received from Verifone here
    systemId = ""
    passCode="";
    systemGuid="";
    payload = "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:com=\"https://www.commidea.webservices.com\">\n   <soap:Header/>\n   <soap:Body>\n      <com:ProcessMsg>\n         <com:Message>\n            <com:ClientHeader>\n               <com:SystemID>" + systemId + "</com:SystemID>\n               <com:SystemGUID>" + systemGuid + "</com:SystemGUID>\n               <com:Passcode>" + passCode + "</com:Passcode>\n               <com:SendAttempt>0</com:SendAttempt>\n               <com:CDATAWrapping>false</com:CDATAWrapping>\n            </com:ClientHeader>\n            <com:MsgType>DETOKENREQUEST</com:MsgType><com:MsgData>&lt;?xml version=\"1.0\"?>&lt;detokenrequest xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns=\"DETOKEN\">&lt;tokenid>" + token + "&lt;/tokenid>&lt;/detokenrequest></com:MsgData>\n         </com:Message>\n      </com:ProcessMsg>\n   </soap:Body>\n</soap:Envelope>"
    response = requests.request("POST", url, headers=headers, data=payload)
    y = json.loads(json.dumps(xmltodict.parse(response.text.encode('utf8'))))
    message = (y["soap:Envelope"]["soap:Body"]["ProcessMsgResponse"]["ProcessMsgResult"]["MsgData"])
    result = json.loads(json.dumps(xmltodict.parse(message)))

    # results
    errorcode = result["detokenresponse"]["errorcode"]
    if errorcode != "0":
        print("No value for token {} errorcode {}".format(token, errorcode))
        # errors_writer.writerow([token, errorcode])
        return []
    else:
        # print("Result {}".format(result))
        pan = result["detokenresponse"]["pan"]
        cardschemename = result["detokenresponse"]["cardschemename"]
        expirydate = result["detokenresponse"]["expirydate"]
        expiryYear = "20" + expirydate[0:2]
        expiryMonth = expirydate[2:4]

        raw_cipher_data = b64decode(pan)
        phn = cipher.decrypt(raw_cipher_data, '')
        # print(phn.decode('Ascii'))

        res = [token, cardschemename, phn.decode('Ascii'), expiryMonth, expiryYear]
        # print("Saving token {}".format(token))
        # csvwriter.writerow(res)
        return res


# this private key is provided by merchant
rsa_key = RSA.importKey(open("path-to-omni-key.pem", "rb").read())
cipher = PKCS1_v1_5.new(rsa_key)

def mp_worker(next_token):
    try:
        return inner(next_token)
    except Exception as e:
       #print(e)
       print("Exception happened for token {}".format(next_token))


resultFileName = "accounts.csv" # file with extracted accounts
def write_accounts(tokens, csvwriter):
    p = Pool(10) #input number of processes here
    accounts = []
    for result in p.imap(mp_worker, tokens):
        if result:
            accounts.append(result)
    p.close()
    p.join()

    with open(resultFileName, "a") as f:
        csvwriter = csv.writer(f)
        csvwriter.writerows(accounts)

def main():
    columns = ['PROVIDER_REFERENCE', 'CardschemeName', 'ACCOUNT_NUMBER', 'ACCOUNT_EXP_MONTH', 'ACCOUNT_EXP_YEAR']
    with open(resultFileName, "w+") as f:
        csvwriter = csv.writer(f)
        csvwriter.writerow(columns)
    
    sourceFileName ="tokensFile.csv" # file with tokens
    with open(sourceFileName, 'r') as file:
        tokens = []
        batchSize = 100
        reader = csv.reader(file)
        for row in reader:
            token = row[1]
            if token not in tokens:
            # print("Adding token {}".format(token)
                tokens.append(token)
            if len(tokens) == batchSize:
                write_accounts(tokens, csvwriter)
                del tokens[:]

        if len(tokens) > 0:
            write_accounts(tokens, csvwriter)

if __name__ == '__main__':
    main()


