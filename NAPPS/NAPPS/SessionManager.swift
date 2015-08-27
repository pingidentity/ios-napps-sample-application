//
//  SessionManager.swift
//

import Foundation

// Helper utility to maintain a user "session" inside the application. This is for demo purposes only (best practise would be to store the tokens in the keychain etc)

class SessionManager {

    var issuer:String?
    var client_id:String?

    var state:String?
    var code_challenge:String?
    var acr_values = "urn:acr:form"
    var redirect_uri = app_redirect_uri
    
    var code:String?
    
    var access_token:String?
    var refresh_token:String?
    var id_token:String?
    
    var isAuthenticated = false
    var inErrorState = false
    var error_code:String?
    var error_description:String?
    var subject:String?
    
    var rawUserInfoResponse:String?
    var userAttributes = [String : AnyObject]()
    
    // Singleton to store the "current" session
    static let currentSession = SessionManager()
    
    func signout() {

        issuer = ""
        client_id = ""
        
        state = ""
        code_challenge = ""
        acr_values = "urn:acr:form"
        redirect_uri = app_redirect_uri
        
        code = ""
        
        access_token = ""
        refresh_token = ""
        id_token = ""
        
        isAuthenticated = false
        inErrorState = false
        error_description = ""
        subject = ""
        
        rawUserInfoResponse = ""
        userAttributes = [:]
    }
}
