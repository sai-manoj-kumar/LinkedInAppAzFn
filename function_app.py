import azure.functions as func
import logging
import hmac
import hashlib
import os
import json
import unicodedata, re, itertools, sys
import re
import html
import time


app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="webhook", methods=["GET"])
def webhook_validation(req: func.HttpRequest) -> func.HttpResponse:
    logRequest(req, "Webhook Validation")
    challengeCode = req.params.get('challengeCode')
    if not challengeCode:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            challengeCode = req_body.get('challengeCode')
    if not challengeCode:
        return func.HttpResponse("No challenge code given")
    

    if "clientSecret" not in os.environ:
        return func.HttpResponse(
            "Client Secret not found"
        )
    
    if not challengeCode:
        logging.info("No ChallengeCode was given")
        return func.HttpResponse(
            "This HTTP triggered function executed, But no challenge code was passed.", status_code=200
        )

    challengeResponse = computeChallengeResponse(challengeCode, os.environ["clientSecret"])
    client_secret = os.environ["clientSecret"]
    response_obj = {"challengeCode": challengeCode, "challengeResponse": challengeResponse, "clientSecret": client_secret[:4]}
    logging.info('Challenge Response Sent')
    return func.HttpResponse(json.dumps(response_obj), mimetype="application/json")

@app.route(route="webhook/{id}/{client_secret}", methods=["GET"])
def webhook_with_id(req: func.HttpRequest, id: str, client_secret: str) -> func.HttpResponse:
    logRequest(req, f"Webhook With ID - {id}")
    
    challengeCode = req.params.get('challengeCode')
    if not challengeCode:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            challengeCode = req_body.get('challengeCode')

    if not challengeCode:
        logging.info("No ChallengeCode was given")
        return func.HttpResponse(
            "This HTTP triggered function executed, But no challenge code was passed.", status_code=200
        )

    # Use the client_secret from the URL instead of env
    challengeResponse = computeChallengeResponse(challengeCode, client_secret)
    response_obj = {"challengeCode": challengeCode, "challengeResponse": challengeResponse}
    logging.info('Challenge Response Sent')
    return func.HttpResponse(json.dumps(response_obj), mimetype="application/json")

    
@app.route(route="webhook", methods=["POST"])
def receive_event(req: func.HttpRequest) -> func.HttpResponse:
    time.sleep(2) # Simulate processing delay
    return func.HttpResponse("OK", status_code=200)

def logRequest(req: func.HttpRequest, callType: str):
    requestLog = [f'Received HTTP call {callType}', f'Method: {req.method}', f'Url {req.url}']
    requestLog.append('Request Headers')
    for (k, v) in req.headers.items():
        requestLog.append(f"{k}: {v}")
    requestLog.append(f"Body: \n{req.get_body()}")
    # requestLog.append(f"Json: \n{req.get_json()}")
    logging.info('\n'.join(requestLog))

def computeChallengeResponse(challengeCode: str, clientSecret: str) -> str:
    return computeHMACDigest(challengeCode, clientSecret)

def computeMessageDigest(req: func.HttpRequest, clientSecret: str) -> str:
    message = str(req.get_body(), 'utf-8')
    logging.info(f"JSON string: {message}")
    return computeHMACDigest(f"hmacsha256={removeSpecialUnicode(message)}", clientSecret)

def computeHMACDigest(message: str, key: str) -> str:
    return hmac.new(
        key=key.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

def removeSpecialUnicode(msg: str) -> str:
    all_chars = (chr(i) for i in range(65536))
    categories = {'Cf'}
    control_chars = ''.join(c for c in all_chars if unicodedata.category(c) in categories)
    # logging.info(f'List of all chars {len(list(all_chars))}')
    # logging.info(f'List of control chars {len(list(control_chars))}')
    # logging.info(control_chars, len(control_chars))
    # or equivalently and much more efficiently
    # control_chars = ''.join(map(chr, itertools.chain(range(0x00,0x20), range(0x7f,0xa0))))
    control_char_re = re.compile('[%s]' % re.escape(control_chars))
    return control_char_re.sub('', msg)
    # return msg
