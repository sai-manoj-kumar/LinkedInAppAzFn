import azure.functions as func
import logging
import hmac
import hashlib
import os
import json


app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="webhook_validation")
def webhook_validation(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
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
        return func.HttpResponse(
            "This HTTP triggered function executed, But no challenge code was passed.", status_code=200
        )

    challengeResponse = computeChallengeResponse(challengeCode, os.environ["clientSecret"])
    client_secret = os.environ["clientSecret"]
    response_obj = {"challengeCode": challengeCode, "challengeResponse": challengeResponse, "clientSecret": client_secret[:4]}
    return func.HttpResponse(json.dumps(response_obj), mimetype="application/json")
    
def computeChallengeResponse(challengeCode: str, clientSecret: str) -> str:
    message = challengeCode
    signature = hmac.new(
        bytes(clientSecret, 'latin-1'), 
        msg=bytes(message, 'latin-1'), 
        digestmod=hashlib.sha256
    ).hexdigest()
    print(signature)
    return signature
