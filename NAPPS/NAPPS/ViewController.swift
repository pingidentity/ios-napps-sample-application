//
//  ViewController.swift
//

import UIKit
import SafariServices

class ViewController: UIViewController, SFSafariViewControllerDelegate {

    @IBOutlet weak var labelAuthenticationResult: UILabel!
    @IBOutlet weak var labelSubject: UILabel!
    @IBOutlet weak var textviewIdToken: UITextView!
    @IBOutlet weak var textviewAccessToken: UITextView!
    @IBOutlet weak var textviewRefreshToken: UITextView!

    @IBOutlet weak var buttonSignIn: UIButton!
    @IBOutlet weak var buttonSignInSilently: UIButton!
    @IBOutlet weak var buttonRefreshAccessToken: UIButton!
    @IBOutlet weak var buttonCallUserInfo: UIButton!
    
    @IBAction func actionSignIn() {

        let authorizationUrl = buildAuthorizationUrl()
        print("*** Using SFSafariViewController to redirect user to authorization url: \(authorizationUrl) ***")
        
        // Present a SFSafariViewController to handle the websso flow
        let safariVC = SFSafariViewController(url: URL(string: authorizationUrl)!)
        safariVC.delegate = self
        present(safariVC, animated: true, completion: nil)
    }
    
    @IBAction func actionSignInSilently() {

        // do a prompt=none re-auth
        let authorizationUrl = buildAuthorizationUrl("none")
        print("*** Using an invisible SFSafariViewController to redirect user to authorization url: \(authorizationUrl) ***")
        
        // Present an invisible SFSafariViewController to handle the websso flow
        let safariVC = SFSafariViewController(url: URL(string: authorizationUrl)!)
        safariVC.delegate = self
        safariVC.modalPresentationStyle = UIModalPresentationStyle.overCurrentContext
        safariVC.view.alpha = 0.0
        present(safariVC, animated: false, completion: nil)
    }
    
    @IBAction func actionRefreshAccessToken() {
        
        refreshOAuthAccessToken()
    }
    
    @IBAction func actionCallUserInfo() {
        
        queryUserInfoEndpoint()

        let userInfoPopup = UIAlertController(title: "UserInfo Results", message: SessionManager.currentSession.rawUserInfoResponse, preferredStyle: UIAlertControllerStyle.alert)
        userInfoPopup.addAction(UIAlertAction(title: "Close", style: UIAlertActionStyle.default,handler: nil))
        
        self.present(userInfoPopup, animated: true, completion: nil)
    }
    
    func updateView() {

        print("*** Updating the view ***")
        
        if (SessionManager.currentSession.inErrorState) {
            labelAuthenticationResult.text = SessionManager.currentSession.error_code
            labelAuthenticationResult.textColor = UIColor.red
        } else {
            
            if (SessionManager.currentSession.isAuthenticated) {
                labelAuthenticationResult.text = "Authentication Sucessful"
                labelAuthenticationResult.textColor = UIColor.green
            } else {
                labelAuthenticationResult.text = "Please Sign In below..."
                labelAuthenticationResult.textColor = UIColor.black
            }
        }
        
        if (SessionManager.currentSession.isAuthenticated) {
            labelSubject.text = SessionManager.currentSession.userAttributes[claims_userName] as? String
            textviewAccessToken.text = SessionManager.currentSession.access_token
            textviewIdToken.text = SessionManager.currentSession.id_token
            textviewRefreshToken.text = SessionManager.currentSession.refresh_token
            
            buttonRefreshAccessToken.isEnabled = true
            buttonCallUserInfo.isEnabled = true
            
        } else {
            
            labelSubject.text = "[Not Logged In]"
            textviewAccessToken.text = "[Not Logged In]"
            textviewIdToken.text = "[Not Logged In]"
            textviewRefreshToken.text = "[Not Logged In]"
            
            buttonRefreshAccessToken.isEnabled = false
            buttonCallUserInfo.isEnabled = false
        }
        self.view.setNeedsDisplay()
    }

    
    //Functions triggered when authentication events occur
    func authenticationComplete() {
        
        DispatchQueue.main.async(execute: {
            self.updateView()
        })
    }
    
    func authenticationFailed() {
        
        DispatchQueue.main.async(execute: {
            self.updateView()
        })
    }

    
    //UIViewController Delegates
    override func viewDidLoad() {
        super.viewDidLoad()
        
        NotificationCenter.default.addObserver(self, selector: #selector(ViewController.authenticationComplete), name: NSNotification.Name(rawValue: "AuthenticationComplete"), object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(ViewController.authenticationFailed), name: NSNotification.Name(rawValue: "AuthenticationFailed"), object: nil)
        
        self.updateView()
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
    }
}

