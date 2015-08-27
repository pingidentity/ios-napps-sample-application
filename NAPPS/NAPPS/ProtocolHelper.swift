//
//  ProtocolHelper.swift
//
// NOTE: These functions are best left to a library to implement. They are included here in a basic form to provide detail around the steps
//       involved with implementing these protocol functions.


import Foundation

// Configuration Settings
let claims_userName:String! = "sub"

let pf_baseUrl:String! = "https://sso.pingdevelopers.com"
let authz_url:String! = "/as/authorization.oauth2"
let token_url:String! = "/as/token.oauth2"
let userinfo_url:String! = "/idp/userinfo.openid"

let scope:String! = "openid profile email"
let issuer:String! = "https://sso.pingdevelopers.com"
let client_id:String! = "ac_client"
let app_redirect_uri:String! = "com.pingidentity.developer.napps://oidc_callback"

let acr_valueOptions = ["urn:acr:form", "urn:acr:x509", "urn:acr:google", "urn:acr:basic", "urn:acr:saml"]


// OpenID Connect / OAuth 2.0 helper functions

// Helper function - Build the authorization request URL
func buildAuthorizationUrl(prompt: String = "") -> String {
    
    // these two parameters MUST be unique values per request to tie the request to the application that requested it
    SessionManager.currentSession.state = NSUUID().UUIDString
    SessionManager.currentSession.code_challenge = NSUUID().UUIDString
    
    var authorizationParameters = Dictionary<String,String>()
    
    authorizationParameters["client_id"] = client_id
    authorizationParameters["response_type"] = "code"
    authorizationParameters["code_challenge"] = SessionManager.currentSession.code_challenge
    authorizationParameters["redirect_uri"] = SessionManager.currentSession.redirect_uri
    authorizationParameters["scope"] = scope
    authorizationParameters["state"] = SessionManager.currentSession.state
    authorizationParameters["acr_values"] = SessionManager.currentSession.acr_values
    if(!prompt.isEmpty) {
        authorizationParameters["prompt"] = prompt
    }

    let authorizationUrl = pf_baseUrl + authz_url + "?" + queryStringFromDictionary(authorizationParameters)
    return authorizationUrl
}

// Authentication step 1 - process the authorization response
func handleAuthorizationResponse(url: NSURL) {
    
    let queryItems = parseAttributes(url.query!, asType: ParseDataType.QueryString)
    
    if let tempError = queryItems["error"] {
        SessionManager.currentSession.inErrorState = true
        SessionManager.currentSession.error_code = tempError as? String
        
        if let tempErrorDescription = queryItems["error_description"] {
            SessionManager.currentSession.error_description = tempErrorDescription.stringByReplacingOccurrencesOfString("+", withString: " ").stringByRemovingPercentEncoding!
        }
    }
    
    // Check that the state matches the value we sent in the request
    if queryItems["state"] as? String != SessionManager.currentSession.state {
        SessionManager.currentSession.inErrorState = true
        SessionManager.currentSession.error_description = "State mismatch"
        return
    }

    if let tempCode = queryItems["code"] {
        SessionManager.currentSession.code = tempCode as? String
    }
    
    if !SessionManager.currentSession.inErrorState {
        
        // Move to step 2 - swap the authorization code for the tokens
        swapAuthorizationCodeForTokens()
    } else {
        
        // There was an error during the authorization request
        NSNotificationCenter.defaultCenter().postNotificationName("AuthenticationFailed", object: nil)
    }
}

// Authentication step 2 - Swap the authorization code for the tokens (access_token, id_token & (optional) refresh_token)
func swapAuthorizationCodeForTokens() {

    // Build the request to the token endpoint
    let tokenUrl = pf_baseUrl + token_url
    
    var postParameters = Dictionary<String,String>()
    postParameters["client_id"] = client_id
    postParameters["grant_type"] = "authorization_code"
    postParameters["code_verifier"] = SessionManager.currentSession.code_challenge
    postParameters["code"] = SessionManager.currentSession.code
    postParameters["redirect_uri"] = SessionManager.currentSession.redirect_uri
    let postData = queryStringFromDictionary(postParameters)

    // POST request to the token endpoint
    print("Performing token request (POST) to \(tokenUrl) with data \(postData)")
    
    let tokenRequest = NSMutableURLRequest(URL: NSURL(string: tokenUrl)!)
    tokenRequest.HTTPMethod = "POST"
    tokenRequest.HTTPBody = postData.dataUsingEncoding(NSUTF8StringEncoding)
    
    let httpRequest = NSURLSession.sharedSession().dataTaskWithRequest(tokenRequest) {
        data, response, error in
        
        // A client-side error occured
        if error != nil {
            SessionManager.currentSession.inErrorState = true
            SessionManager.currentSession.error_description = (error?.description)!
            return
        }
        
        let responseCode = (response as! NSHTTPURLResponse).statusCode
        let responseData = NSString(data: data!, encoding: NSUTF8StringEncoding)
        print("Received Response (\(responseCode)): \(responseData)")
        
        let responseItems = parseAttributes(responseData!, asType: ParseDataType.JSON)
        
        // 200 - Successful token exchange
        if responseCode == 200 {
            
            if let tempAccessToken = responseItems["access_token"] {
                SessionManager.currentSession.access_token = tempAccessToken as? String
            }
            
            if let tempIdToken = responseItems["id_token"] {
                SessionManager.currentSession.id_token = tempIdToken as? String
            }
            
            if let tempRefreshToken = responseItems["refresh_token"] {
                SessionManager.currentSession.refresh_token = tempRefreshToken as? String
            }
        // 400 - Token exchange failed
        } else if responseCode == 400 {
            
            SessionManager.currentSession.inErrorState = true

            if let errorResult = responseItems["error"] {
                SessionManager.currentSession.error_code = errorResult as? String
                SessionManager.currentSession.error_description = responseItems["error_description"] as? String
            }
        }

        if !SessionManager.currentSession.inErrorState {
            
            // Move to step 3 - Validate the ID Token
            validateIdToken()
        } else {
            
            // An error occured during the HTTP request to the token endpoint
            NSNotificationCenter.defaultCenter().postNotificationName("AuthenticationFailed", object: nil)
        }
    }
    httpRequest.resume()
}

// Authentication step 3 - Validate the id_token to retrieve the authenticated user subject
func validateIdToken() {
    
    // Note: We are using the OpenID Connect Basic Profile and because we got the id_token direct from the token endpoint, we don't need to validate the signature
    // id_token is a JWT which is [header].[payload].[signature] - we are only concerned with the payload contents
    // iOS doesn't have a base64urldecode function so we need to "convert" the base64urlencoded string to a base64encoded string
    let idTokenPayloadString = base64EncodedStringFromBase64UrlEncodedString(SessionManager.currentSession.id_token!.componentsSeparatedByString(".")[1])
    
    let idTokenPayload = NSString(data: NSData(base64EncodedString: idTokenPayloadString, options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters)!, encoding: NSUTF8StringEncoding)
    let idTokenAttributes = parseAttributes(idTokenPayload!, asType: ParseDataType.JSON)
    
    // Check the issuer matches the issuer
    if idTokenAttributes["iss"] as! String != issuer {
        SessionManager.currentSession.inErrorState = true
        SessionManager.currentSession.error_description = "Invalid Issuer"
    }

    // Check the audience matches the client_id
    if idTokenAttributes["aud"] as! String != client_id {
        SessionManager.currentSession.inErrorState = true
        SessionManager.currentSession.error_description = "Invalid Audience"
    }

    // Check the token hasn't expired
    if idTokenAttributes["exp"] != nil {
        let expires = NSDate(timeIntervalSince1970: idTokenAttributes["exp"] as! Double)
        
        if expires.compare(NSDate()) == NSComparisonResult.OrderedAscending {
            SessionManager.currentSession.inErrorState = true
            SessionManager.currentSession.error_description = "Token Expired"
        }
    }
    
    // Store the subject of the id_token (to compare later against the userinfo data)
    if let tempIdTokenSubject = idTokenAttributes["sub"] {
        SessionManager.currentSession.subject = tempIdTokenSubject as? String
    }
    
    if !SessionManager.currentSession.inErrorState {

        // Move to step 4 - Query the UserInfo endpoint to retrieve additional attributes
        queryUserInfoEndpoint()
    } else {
        
        // An error occurred validating the id_token
        NSNotificationCenter.defaultCenter().postNotificationName("AuthenticationFailed", object: nil)
    }
}

// Authentication step 4 (optional) - Query the UserInfo endpoint to retrieve additional attributes about the user
func queryUserInfoEndpoint() {
    
    let userInfoUrl = pf_baseUrl + userinfo_url

    // Form a GET request using the OAuth access_token as Bearer credentials
    let userInfoRequest = NSMutableURLRequest(URL: NSURL(string: userInfoUrl)!)
    userInfoRequest.HTTPMethod = "GET"
    userInfoRequest.setValue("Bearer \(SessionManager.currentSession.access_token!)", forHTTPHeaderField: "Authorization")
    
    print("Set Authorization header to: Bearer \(SessionManager.currentSession.access_token!)")
    
    let httpRequest = NSURLSession.sharedSession().dataTaskWithRequest(userInfoRequest) {
        data, response, error in
        
        if error != nil {
            print("HTTP Request Error: \(error)")
            SessionManager.currentSession.inErrorState = true
            SessionManager.currentSession.error_description = (error?.description)!
            return
        }
        
        let responseCode = (response as! NSHTTPURLResponse).statusCode
        let responseData = NSString(data: data!, encoding: NSUTF8StringEncoding)
        print("Received Response (\(responseCode)): \(responseData)")
        
        SessionManager.currentSession.rawUserInfoResponse = responseData as? String
        let userInfoAttributes = parseAttributes(SessionManager.currentSession.rawUserInfoResponse!, asType: ParseDataType.JSON)
        
        if !SessionManager.currentSession.inErrorState {
            
            // The subject of the id_token MUST match the subject of the UserInfo claims
            if userInfoAttributes["sub"] as? String != SessionManager.currentSession.subject {
                
                SessionManager.currentSession.inErrorState = true
                SessionManager.currentSession.error_description = "UserInfo does not match id_token"
                
                NSNotificationCenter.defaultCenter().postNotificationName("AuthenticationFailed", object: nil)
            } else {
                
                // Thats it! We have an authenticated user and their attributes
                SessionManager.currentSession.isAuthenticated = true
                SessionManager.currentSession.userAttributes = userInfoAttributes
                
                // Notify listeners that an authentication event is complete
                NSNotificationCenter.defaultCenter().postNotificationName("AuthenticationComplete", object: nil)
            }
        } else {
            
            // An error occurred querying the UserInfo endpoint
            NSNotificationCenter.defaultCenter().postNotificationName("AuthenticationFailed", object: nil)
        }
    }
    httpRequest.resume()
}

func refreshOAuthAccessToken() {
    
    // Build the request to the token endpoint
    let tokenUrl = pf_baseUrl + token_url
    
    var postParameters = Dictionary<String,String>()
    postParameters["client_id"] = client_id
    postParameters["grant_type"] = "refresh_token"
    postParameters["refresh_token"] = SessionManager.currentSession.refresh_token
    let postData = queryStringFromDictionary(postParameters)
    
    // POST request to the token endpoint
    print("Performing token request (POST) to \(tokenUrl) with data \(postData)")
    
    let tokenRequest = NSMutableURLRequest(URL: NSURL(string: tokenUrl)!)
    tokenRequest.HTTPMethod = "POST"
    tokenRequest.HTTPBody = postData.dataUsingEncoding(NSUTF8StringEncoding)
    
    let httpRequest = NSURLSession.sharedSession().dataTaskWithRequest(tokenRequest) {
        data, response, error in
        
        // A client-side error occured
        if error != nil {
            SessionManager.currentSession.inErrorState = true
            SessionManager.currentSession.error_description = (error?.description)!
            return
        }
        
        let responseCode = (response as! NSHTTPURLResponse).statusCode
        let responseData = NSString(data: data!, encoding: NSUTF8StringEncoding)
        print("Received Response (\(responseCode)): \(responseData)")
        
        let responseItems = parseAttributes(responseData!, asType: ParseDataType.JSON)
        
        // 200 - Successful token request
        if responseCode == 200 {
            
            if let tempAccessToken = responseItems["access_token"] {
                SessionManager.currentSession.access_token = tempAccessToken as? String
            }
            
            if let tempIdToken = responseItems["id_token"] {
                SessionManager.currentSession.id_token = tempIdToken as? String
            }
            
            if let tempRefreshToken = responseItems["refresh_token"] {
                SessionManager.currentSession.refresh_token = tempRefreshToken as? String
            }
            
        // 400 - Token request failed
        } else if responseCode == 400 {
            
            SessionManager.currentSession.inErrorState = true
            
            if let errorResult = responseItems["error"] {
                SessionManager.currentSession.error_code = errorResult as? String
                SessionManager.currentSession.error_description = responseItems["error_description"] as? String
            }
        }
        
        if !SessionManager.currentSession.inErrorState {
            
            // Notify that the request succeeded so we can refresh the view
            NSNotificationCenter.defaultCenter().postNotificationName("AuthenticationComplete", object: nil)
        } else {
            
            // An error occured during the HTTP request to the token endpoint
            NSNotificationCenter.defaultCenter().postNotificationName("AuthenticationFailed", object: nil)
        }
    }
    httpRequest.resume()
}


// General utility functions

enum ParseDataType {
    case QueryString
    case JSON
}

//This function is to simplify the building of the querystring and form post body.
func queryStringFromDictionary(dictionary:Dictionary<String,AnyObject>) -> String {

    
    var queryString = ""
    var firstParam = true
    
    for queryParam in dictionary.keys {
        if (!firstParam) { queryString += "&" } // if this is not the first param, pre-pend by &
        let encodedParam = queryParam.stringByAddingPercentEncodingWithAllowedCharacters(.URLHostAllowedCharacterSet());
        let encodedValue = (dictionary[queryParam] as! String).stringByAddingPercentEncodingWithAllowedCharacters(.URLHostAllowedCharacterSet())
        
        queryString += "\(encodedParam!)=\(encodedValue!)"
        firstParam = false
    }
    
    return queryString
}

//This function is to simplify parsing of a querystring or JSON response into a dictionary
func parseAttributes(fromStringData:NSString, asType:ParseDataType) -> [String: AnyObject] {
    
    var returnDictionary = [String: AnyObject]()
    
    if asType == ParseDataType.QueryString {
        for queryParam in fromStringData.componentsSeparatedByString("&") {
            print("Parsing query parameter: \(queryParam)")
            var queryElement = queryParam.componentsSeparatedByString("=")
            returnDictionary[queryElement[0]] = queryElement[1]
        }
    } else {
        print("Parsing JSON data: \(fromStringData)")
        let jsonData = fromStringData.dataUsingEncoding(NSUTF8StringEncoding)
        do {
            returnDictionary = try (NSJSONSerialization.JSONObjectWithData(jsonData!, options: NSJSONReadingOptions.MutableContainers) as? [String: AnyObject])!
        } catch {
            print("Error - \(error)")
        }
    }
    
    return returnDictionary
}

// iOS supports base64 encoding and decoding however not base64URl encoding and decoding this covers that gap
func base64EncodedStringFromBase64UrlEncodedString(base64UrlEncodedString:String) -> String {
    
    // Add padding to the end of the string
    var numEqualsNeeded = 4 - (base64UrlEncodedString.characters.count % 4)
    if (numEqualsNeeded == 4) { numEqualsNeeded = 0; }
    var padding = ""
    
    for var i = 0; i < numEqualsNeeded; ++i {
        padding += "="
    }
    
    // Replace _ with / and - with +
    let base64EncodedString = base64UrlEncodedString.stringByReplacingOccurrencesOfString("_", withString: "/").stringByReplacingOccurrencesOfString("-", withString: "+") + padding
    
    return base64EncodedString
}
