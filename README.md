# iOS9 NAPPS Sample Application

**ios-napps-sample-application** is a basic sample application to demonstrate using the new SFSafariViewController in iOS9 to facilitate native application single sign-on (NAPPS).

This sample application will authenticate the user via OpenID Connect 1.0 and present the user's subject and tokens on the screen. Options to refresh the OAuth 2.0 access token and to refresh the authentication session are also demonstrated.

Refer to the **Native Application SSO Developers Guide** at https://developer.pingidentity.com/en/napps-native-app-sso for more detailed information.


## Installation

This sample application has been built using PingFederate 8.0.1 and the OAuth Playground 3.2. Follow the documentation for PingFederate and the OAuth Playground to quickly stand up an OpenID Connect Provider / OAuth Authorization Server.

Modify the "ProtocolHelper.swift" file with the URL of your PingFederate server and the name of your issuer.

Note: Due to the Application Transport Security (ATS) feature of iOS9, your PingFederate server must have a valid SSL certificate.


## Disclaimer

*This software is open sourced by Ping Identity but not supported commercially as such. Any questions/issues/comments should be directed to the "Developer Q&A" group in the Ping Identity Support Communities https://community.pingidentity.com/collaborate.*
