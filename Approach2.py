import urllib, urllib2, urlparse
# This sample shows how to obtain an OAuth access token
# without the user/browser flow
# Dexcom OAuth client ID
client_id = "DAEC20AC-9626-4B0E-94B5-B674E298F51E"
#client_secret = 'client_secret_here' 
#base_url ="https://api.dexcom.com/v2/oauth2"
base_url = 'https://uam1.dexcom.com/identity/connect'
api_url = "https://clarity.dexcom.com/api/subject/1594950620847472640/analysis_session"
# put login credentials here
username = "nilepatest001"
password = "Password@1"

class AuthCodeRedirectHandler(urllib2.HTTPRedirectHandler):
    """
     redirect handler that pulls the auth code sent back
    by OAuth off the query string of the redirect URI given in the
    Location header.  Does no checking for other errors or bad/missing
    information.
    """
    def http_error_302(self, req, fp, code, msg, headers):
        """handler for 302 responses that assumes a properly constructed
        OAuth 302 response and pulls the auth code out of the header"""
        
        qs = urlparse.urlparse(headers["location"]).query
        auth_code = urlparse.parse_qs(qs)['code'][0]
        return auth_code


def build_auth_code_request(username, password):
    """This method builds the URL request with the below necessary parameters"""
    auth_data = urllib.urlencode({
            "client_id": client_id,
            "response_type": "code",
            "username": username,
            "password": password,
            "action": "Login",
            "scope":"openid profile offline_access",
            "redirect_uri" :"https://clarity.dexcom.com/users/auth/dexcom_sts/callback",
    })
  
    req = urllib2.Request(url=base_url + "/authorize"+auth_data)
    return req

def get_access_token(code):
    """
    Gets an OAuth access token given an OAuth authorization code
    """
    access_token_params = urllib.urlencode({
        'grant_type': 'authorization_code',
        'client_id': client_id,
        'code': code
    })
    req = urllib2.Request(base_url + '/token', access_token_params)
    f = urllib2.urlopen(req)
    return f.read()


if __name__ == "__main__":
    req = build_auth_code_request(username, password)
    opener = urllib2.build_opener(AuthCodeRedirectHandler)

    auth_code = opener.open(req) 
    print(auth_code) #print the auth code that is retrieved from the redirect URI
    access_token = get_access_token(auth_code)
    print(access_token)
    
    #Do a post request on the API endpoint URL by passing the access token in the header.
    response = requests.request("POST", api_url, headers=access_token) 
    #Parsing the Json String into python dictionary
    result = json.loads(response.text)
    #Assert that the analysisSessionId is not NULL and if it is NUll, display the Assert Error
    assert (result["analysisSessionId"]!=None),"The AnalysisSessionId is NULL"
    print("The analysis session ID value is " +result["analysisSessionId"])
