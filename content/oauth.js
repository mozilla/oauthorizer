/* ***** BEGIN LICENSE BLOCK *****
* Version: MPL 1.1/GPL 2.0/LGPL 2.1
*
* The contents of this file are subject to the Mozilla Public License Version
* 1.1 (the "License"); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
* for the specific language governing rights and limitations under the
* License.
*
* The Original Code is FireUploader
*
* The Initial Developer of the Original Code is Rahul Jonna.
*
* Portions created by the Initial Developer are Copyright (C) 2007-2009
* the Initial Developer. All Rights Reserved.
*
* Alternatively, the contents of this file may be used under the terms of
* either the GNU General Public License Version 2 or later (the "GPL"), or
* the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
* in which case the provisions of the GPL or the LGPL are applicable instead
* of those above. If you wish to allow use of your version of this file only
* under the terms of either the GPL or the LGPL, and not to allow others to
* use your version of this file under the terms of the MPL, indicate your
* decision by deleting the provisions above and replace them with the notice
* and other provisions required by the GPL or the LGPL. If you do not delete
* the provisions above, a recipient may use your version of this file under
* the terms of any one of the MPL, the GPL or the LGPL.
*
* ***** END LICENSE BLOCK ***** */

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

Components.utils.import("resource://oauthorizer/modules/oauth.js");
Components.utils.import("resource://oauthorizer/modules/Log4Moz.js");

var OAuthConsumer = {};

(function()
{

    this._providers = {
        "yahoo": function(key, secret) {
            return {
                name: "Yahoo!",
                consumerKey   : key, 
                consumerSecret: secret,
                token: null,
                accessorSecret: null,
                tokenSecret: null,
                serviceProvider:
                {
                  signatureMethod     : "HMAC-SHA1",
                  requestTokenURL     : "https://api.login.yahoo.com/oauth/v2/get_request_token",
                  userAuthorizationURL: "https://api.login.yahoo.com/oauth/v2/request_auth",
                  accessTokenURL      : "https://api.login.yahoo.com/oauth/v2/get_token", 
                  echoURL             : ""
                }
            }
        }
    };
    
    this.getProvider = function(providerName, key, secret) {
        return this._providers[providerName](key, secret);
    }
    
    this.Authorizer = function myauthorizer (oauthSvc, afterAuthorizeCallback) {
        this._log = SimpleLogger.getLogger("oath.authorizer", "oauth.txt", true, true, false);
        this.service = oauthSvc
        this.afterAuthorizeCallback = afterAuthorizeCallback;
    }
    this.Authorizer.prototype = {
        
        //starts the authentication process	
        startAuthentication: function()
        {
            this.getRequestToken();
        },

        getRequestToken: function() {
        
            this._log.debug("Getting "+this.service.name+" request token");
        
            var message = {
                method: "POST", 
                action: this.service.serviceProvider.requestTokenURL,
                parameters: {
                    // we fake this big time so we can catch a redirect
                  oauth_callback: "http://oauthcallback.local/access.xhtml"
                  // TODO xoauth_lang_pref
                }
            };
            OAuth.completeRequest(message, this.service);
            var requestBody = OAuth.formEncode(message.parameters);
            this._log.debug("REQUEST: "+requestBody);
        
            var authorizationHeader = OAuth.getAuthorizationHeader("", message.parameters);
            var requestToken = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                                    .createInstance(Components.interfaces.nsIXMLHttpRequest);
        
            let self = this;
            requestToken.onreadystatechange = function receiveRequestToken() {
                if (requestToken.readyState == 4) {
                    var dump = requestToken.status+" "+requestToken.statusText
                          +"\n\n"+requestToken.getAllResponseHeaders()
                          +"\n"+requestToken.responseText + "\n\n";
                    self._log.debug("Successful requestToken: " + dump);
                    var results = OAuth.decodeForm(requestToken.responseText);
                    let token = OAuth.getParameter(results, "oauth_token");
                    //let auth_url = OAuth.getParameter(results, "xoauth_request_auth_url") ||
                    //                self.service.serviceProvider.userAuthorizationURL;
                    //self._log.debug("auth_url: "+auth_url);
                    openOAuthLogin(self.service.serviceProvider.userAuthorizationURL,
                                   results, token,
                                   function(results, accessToken) {
                                        self.getAccessToken(results, accessToken);
                                    });
                }
            };
            requestToken.open(message.method, message.action, true); 
            requestToken.setRequestHeader("Authorization", authorizationHeader);
            requestToken.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            requestToken.send(requestBody);
        },


        getAccessToken: function(requestTokenResults, accessToken)
        {
            try {
          this._log.debug("Getting "+this.service.name+
                          " access token: "+accessToken+" requestToken is " +
                          JSON.stringify(requestTokenResults));
        
          this.service.tokenSecret = OAuth.getParameter(requestTokenResults, "oauth_token_secret");
          this._log.debug("   tokenSecret: "+this.service.tokenSecret)
          message = {
            method: "POST", 
            action: this.service.serviceProvider.accessTokenURL,
            parameters: {
              oauth_signature_method: "HMAC-SHA1",
              oauth_verifier: accessToken,
              oauth_token   : OAuth.getParameter(requestTokenResults, "oauth_token")
            }
          };
          OAuth.completeRequest(message, this.service);
          var requestBody = OAuth.formEncode(message.parameters);
        this._log.debug("REQUEST: "+requestBody);
          
          var requestAccess = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                                    .createInstance(Components.interfaces.nsIXMLHttpRequest);
        
        let self = this;
          requestAccess.onreadystatechange = function receiveAccessToken() {
            var results = null;
              if (requestAccess.readyState == 4) {
                self._log.debug("Finished getting "+self.service.name+
                                " request token: " + requestAccess.status+" "+requestAccess.statusText
                  +"\n"+requestAccess.getAllResponseHeaders()+"\n"+requestAccess.responseText);
                  
                results = OAuth.decodeForm(requestAccess.responseText);
                
                self.service.token = OAuth.getParameter(results, "oauth_token");
                self.service.tokenSecret = OAuth.getParameter(results, "oauth_token_secret");
                self.service.access_params = results;

                self.afterAuthorizeCallback(true);
              }
          };
          requestAccess.open(message.method, message.action, true); 
          requestAccess.setRequestHeader("Authorization", OAuth.getAuthorizationHeader("", message.parameters));
          requestAccess.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
          requestAccess.send(requestBody);
            } catch(e) {
                this._log.error(e);
            }
        }

    };

}).call(OAuthConsumer);

