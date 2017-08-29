//
//  ProtocolHelper.swift
//
// NOTE: These functions are best left to a library to implement. They are included here in a basic form to provide detail around the steps
//       involved with implementing these protocol functions.


import Foundation

// Configuration Settings
let claims_userName:String! = "sub"

let pf_baseUrl:String! = "https://accounts.google.com"
let pf_baseAPIUrl:String! = "https://www.googleapis.com"
let authz_url:String! = "/o/oauth2/v2/auth"
let token_url:String! = "/oauth2/v4/token"
let userinfo_url:String! = "/oauth2/v3/userinfo"

let scope:String! = "email"
let issuer:String! = "https://accounts.google.com"
let client_id:String! = "1085300139846-j6ro8c8hmajlftpm1h7q5vhd2ik0m6or.apps.googleusercontent.com"
let app_redirect_uri:String! = "com.googleusercontent.apps.1085300139846-j6ro8c8hmajlftpm1h7q5vhd2ik0m6or:/oauthredirect"

//{"web":{"client_id":"35903393178-u2lj1208b6pf49e1naprkco02h7hkki6.apps.googleusercontent.com",
//    "project_id":"squawker-269e0","auth_uri":"https://accounts.google.com/o/oauth2/auth",
//    "token_uri":"https://accounts.google.com/o/oauth2/token",
//    "auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs",
//    "client_secret":"tCPNY2iAoQmndUDPT0u19qsK",
//    "redirect_uris":["https://squawker-269e0.firebaseapp.com/__/auth/handler"],
//    "javascript_origins":["http://localhost","http://localhost:5000","https://squawker-269e0.firebaseapp.com"]}}
// OpenID Connect / OAuth 2.0 helper functions

// Helper function - Build the authorization request URL
func buildAuthorizationUrl(_ prompt: String = "") -> String {
    
    print("*** Building authorization URL ***")
    
    // these two parameters MUST be unique values per request to tie the request to the application that requested it
    SessionManager.currentSession.state = UUID().uuidString
    SessionManager.currentSession.code_challenge = UUID().uuidString
    
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

    let authorizationUrl = pf_baseUrl + authz_url + "?" + queryStringFromDictionary(authorizationParameters as Dictionary<String, AnyObject>)
    return authorizationUrl
}

// Authentication step 1 - process the authorization response
func handleAuthorizationResponse(_ url: URL) {

    print("*** Processing the authorization response ***")

    let queryItems = parseAttributes(url.query!, asType: ParseDataType.queryString)
    
    if let tempError = queryItems["error"] {
        SessionManager.currentSession.inErrorState = true
        SessionManager.currentSession.error_code = tempError as? String
        
        if let tempErrorDescription = queryItems["error_description"] {
            SessionManager.currentSession.error_description = tempErrorDescription.replacingOccurrences(of: "+", with: " ").removingPercentEncoding!
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
        NotificationCenter.default.post(name: Notification.Name(rawValue: "AuthenticationFailed"), object: nil)
    }
}

// Authentication step 2 - Swap the authorization code for the tokens (access_token, id_token & (optional) refresh_token)
func swapAuthorizationCodeForTokens() {

    print("*** Exchanging the authorization code for the tokens ***")

    // Build the request to the token endpoint
    let tokenUrl = pf_baseAPIUrl + token_url
    
    var postParameters = Dictionary<String,String>()
    postParameters["client_id"] = client_id
    postParameters["grant_type"] = "authorization_code"
    postParameters["code_verifier"] = SessionManager.currentSession.code_challenge
    postParameters["code"] = SessionManager.currentSession.code
    postParameters["redirect_uri"] = SessionManager.currentSession.redirect_uri
    let postData = queryStringFromDictionary(postParameters as Dictionary<String, AnyObject>)

    // POST request to the token endpoint
    print("Performing token request (POST) to \(tokenUrl) with data \(postData)")
    
    var tokenRequest = URLRequest(url: URL(string: tokenUrl)!)
    tokenRequest.httpMethod = "POST"
    tokenRequest.setValue("application/x-www-form-urlencoded; charset=UTF-8", forHTTPHeaderField: "Content-Type")
    tokenRequest.setValue("application/json", forHTTPHeaderField: "Accept")

    tokenRequest.httpBody = postData.data(using: .utf8, allowLossyConversion: true)
    
    URLSession.shared.dataTask(with: tokenRequest) { (data, response, error) in
        
        // A client-side error occured
        if error != nil {
            SessionManager.currentSession.inErrorState = true
            SessionManager.currentSession.error_description = (error?.localizedDescription)!
            return
        }
        
        let responseCode = (response as! HTTPURLResponse).statusCode
        let responseData = String(data: data!, encoding:.utf8)
        print("Received Response (\(responseCode)): \(String(describing: responseData))")
        
        let responseItems = parseAttributes(responseData!, asType: ParseDataType.json)
        
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
            print("!!! An error occurred: \(String(describing: SessionManager.currentSession.error_code)) !!!")
            // An error occured during the HTTP request to the token endpoint
            NotificationCenter.default.post(name: Notification.Name(rawValue: "AuthenticationFailed"), object: nil)
        }
        }.resume()
    
    
}

// Authentication step 3 - Validate the id_token to retrieve the authenticated user subject
func validateIdToken() {
    
    print("*** Validating the ID token ***")
    
    // Note: We are using the OpenID Connect Basic Profile and because we got the id_token direct from the token endpoint, we don't need to validate the signature
    // id_token is a JWT which is [header].[payload].[signature] - we are only concerned with the payload contents
    // iOS doesn't have a base64urldecode function so we need to "convert" the base64urlencoded string to a base64encoded string
    if let string = (SessionManager.currentSession.id_token?.components(separatedBy: ".")[1]) {
        
        let idTokenPayloadString = base64EncodedStringFromBase64UrlEncodedString(string)
        let data = Data(base64Encoded: idTokenPayloadString, options: .ignoreUnknownCharacters)!
        let idTokenPayload = String(data:data, encoding:.utf8)
        let idTokenAttributes = parseAttributes(idTokenPayload!, asType: ParseDataType.json)
        
        // Check the issuer matches the issuer
        if idTokenAttributes["iss"] as? String != issuer {
            let idTokenIssuer = idTokenAttributes["iss"]
            print("Error: Invalid issuer - \(String(describing: idTokenIssuer)) != \(issuer)")
            SessionManager.currentSession.inErrorState = true
            SessionManager.currentSession.error_description = "Invalid Issuer"
        }
        
        // Check the audience matches the client_id
        if idTokenAttributes["aud"] as? String != client_id {
            let idTokenAudience = idTokenAttributes["aud"]
            print("Error: Invalid audience - \(String(describing: idTokenAudience)) != \(client_id)")
            SessionManager.currentSession.inErrorState = true
            SessionManager.currentSession.error_description = "Invalid Audience"
        }
        
        // Check the token hasn't expired
        if idTokenAttributes["exp"] != nil {
            let expires = Date(timeIntervalSince1970: idTokenAttributes["exp"] as! Double)
            
            if expires.compare(Date()) == ComparisonResult.orderedAscending {
                print("Error: ID token has expired")
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
            print("!!! An error occurred: \(String(describing: SessionManager.currentSession.error_code)) !!!")
            // An error occurred validating the id_token
            NotificationCenter.default.post(name: Notification.Name(rawValue: "AuthenticationFailed"), object: nil)
        }
    }
}

// Authentication step 4 (optional) - Query the UserInfo endpoint to retrieve additional attributes about the user
func queryUserInfoEndpoint() {
    
    print("*** Querying the UserInfo endpoint ***")

    let userInfoUrl = pf_baseAPIUrl + userinfo_url

    // Form a GET request using the OAuth access_token as Bearer credentials
    var userInfoRequest = URLRequest(url: URL(string: userInfoUrl)!)
    userInfoRequest.httpMethod = "GET"
    userInfoRequest.setValue("Bearer \(SessionManager.currentSession.access_token!)", forHTTPHeaderField: "Authorization")
    
    print("Set Authorization header to: Bearer \(SessionManager.currentSession.access_token!)")
    
    let httpRequest = URLSession.shared.dataTask(with: userInfoRequest, completionHandler: {
        data, response, error in
        
        if error != nil {
            print("HTTP Request Error: \(String(describing: error))")
            SessionManager.currentSession.inErrorState = true
            SessionManager.currentSession.error_description = (error?.localizedDescription)!
            return
        }
        
        let responseCode = (response as! HTTPURLResponse).statusCode
        let responseData = String(data: data!, encoding: .utf8)
        print("Received Response (\(responseCode)): \(String(describing: responseData))")
        
        SessionManager.currentSession.rawUserInfoResponse = responseData
        let userInfoAttributes = parseAttributes(SessionManager.currentSession.rawUserInfoResponse!, asType: ParseDataType.json)
        
        if !SessionManager.currentSession.inErrorState {
            
            // The subject of the id_token MUST match the subject of the UserInfo claims
            if userInfoAttributes["sub"] as? String != SessionManager.currentSession.subject {
                
                SessionManager.currentSession.inErrorState = true
                SessionManager.currentSession.error_description = "UserInfo does not match id_token"
                
                NotificationCenter.default.post(name: Notification.Name(rawValue: "AuthenticationFailed"), object: nil)
            } else {
                
                // Thats it! We have an authenticated user and their attributes
                SessionManager.currentSession.isAuthenticated = true
                SessionManager.currentSession.userAttributes = userInfoAttributes
                
                // Notify listeners that an authentication event is complete
                NotificationCenter.default.post(name: Notification.Name(rawValue: "AuthenticationComplete"), object: nil)
            }
        } else {
            print("!!! An error occurred: \(String(describing: SessionManager.currentSession.error_code)) !!!")
            // An error occurred querying the UserInfo endpoint
            NotificationCenter.default.post(name: Notification.Name(rawValue: "AuthenticationFailed"), object: nil)
        }
    }) 
    httpRequest.resume()
}

func refreshOAuthAccessToken() {
    
    print("*** Refreshing the OAuth access token ***")
    
    // Build the request to the token endpoint
    let tokenUrl = pf_baseAPIUrl + token_url
    
    var postParameters = Dictionary<String,String>()
    postParameters["client_id"] = client_id
    postParameters["grant_type"] = "refresh_token"
    postParameters["refresh_token"] = SessionManager.currentSession.refresh_token
    let postData = queryStringFromDictionary(postParameters as Dictionary<String, AnyObject>)
    
    // POST request to the token endpoint
    print("Performing token request (POST) to \(tokenUrl) with data \(postData)")
    
    var tokenRequest = URLRequest(url: URL(string: tokenUrl)!)
    tokenRequest.httpMethod = "POST"
    tokenRequest.setValue("application/x-www-form-urlencoded; charset=UTF-8", forHTTPHeaderField: "Content-Type")
    tokenRequest.setValue("application/json", forHTTPHeaderField: "Accept")
    tokenRequest.httpBody = postData.data(using: .utf8)
    
    let httpRequest = URLSession.shared.dataTask(with: tokenRequest, completionHandler: {
        data, response, error in
        
        // A client-side error occured
        if error != nil {
            SessionManager.currentSession.inErrorState = true
            SessionManager.currentSession.error_description = (error?.localizedDescription)!
            return
        }
        
        let responseCode = (response as! HTTPURLResponse).statusCode
        let responseData = String(data: data!, encoding: .utf8)
        print("Received Response (\(responseCode)): \(String(describing: responseData))")
        
        let responseItems = parseAttributes(responseData!, asType: ParseDataType.json)
        
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
            NotificationCenter.default.post(name: Notification.Name(rawValue: "AuthenticationComplete"), object: nil)
        } else {
            print("!!! An error occurred: \(String(describing: SessionManager.currentSession.error_code)) !!!")
            // An error occured during the HTTP request to the token endpoint
            NotificationCenter.default.post(name: Notification.Name(rawValue: "AuthenticationFailed"), object: nil)
        }
    }) 
    httpRequest.resume()
}


// General utility functions

enum ParseDataType {
    case queryString
    case json
}

//This function is to simplify the building of the querystring and form post body.
func queryStringFromDictionary(_ dictionary:Dictionary<String,AnyObject>) -> String {

    
    var queryString = ""
    var firstParam = true
    
    for queryParam in dictionary.keys {
        if (!firstParam) { queryString += "&" } // if this is not the first param, pre-pend by &
        let encodedParam = queryParam.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed);
        let encodedValue = (dictionary[queryParam] as! String).addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)
        
        queryString += "\(encodedParam!)=\(encodedValue!)"
        firstParam = false
    }
    
    return queryString
}

//This function is to simplify parsing of a querystring or JSON response into a dictionary
func parseAttributes(_ fromStringData: String, asType:ParseDataType) -> [String: AnyObject] {
    
    var returnDictionary = [String: AnyObject]()
    
    if asType == ParseDataType.queryString {
        for queryParam in fromStringData.components(separatedBy: "&") {
            print("Parsing query parameter: \(queryParam)")
            var queryElement = queryParam.components(separatedBy: "=")
            returnDictionary[queryElement[0]] = queryElement[1] as AnyObject
        }
    } else {
        print("Parsing JSON data: \(fromStringData)")
        let jsonData = fromStringData.data(using: .utf8)
        do {
            returnDictionary = try (JSONSerialization.jsonObject(with: jsonData!, options: JSONSerialization.ReadingOptions.mutableContainers) as? [String: AnyObject])!
        } catch {
            print("Error - \(error)")
        }
    }
    
    return returnDictionary
}

// iOS supports base64 encoding and decoding however not base64URl encoding and decoding this covers that gap
func base64EncodedStringFromBase64UrlEncodedString(_ base64UrlEncodedString:String) -> String {
    
    // Add padding to the end of the string
    var numEqualsNeeded = 4 - (base64UrlEncodedString.characters.count % 4)
    if (numEqualsNeeded == 4) { numEqualsNeeded = 0; }
    var padding = ""
    
    for _ in 0 ..< numEqualsNeeded {
        padding += "="
    }
    
    // Replace _ with / and - with +
    let base64EncodedString = base64UrlEncodedString.replacingOccurrences(of: "_", with: "/")
        .replacingOccurrences(of: "-", with: "+") + padding
    
    return base64EncodedString
}

