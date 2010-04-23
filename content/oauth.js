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
    var COMPLETION_URI = "http://oauthcallback.local/access.xhtml";
    this._providers = {
        // while some providers support POST, it seems all providers work
        // with GET, so use GET
        "yahoo": function(key, secret) {
            return {
                name: "Yahoo!",
                version: "1.0",
                consumerKey   : key, 
                consumerSecret: secret,
                token: null,       // oauth_token
                tokenSecret: null, // oauth_token_secret
                accessParams: {},  // results from request access
                requestParams: {}, // results from request token
                requestMethod: "GET",
                serviceProvider:
                {
                  signatureMethod     : "HMAC-SHA1",
                  requestTokenURL     : "https://api.login.yahoo.com/oauth/v2/get_request_token",
                  userAuthorizationURL: "https://api.login.yahoo.com/oauth/v2/request_auth",
                  accessTokenURL      : "https://api.login.yahoo.com/oauth/v2/get_token", 
                  echoURL             : ""
                }
            }
        },
        "google": function(key, secret) {
            return {
                name: "Google",
                version: "1.0",
                consumerKey   : key, 
                consumerSecret: secret,
                token: null,
                tokenSecret: null,
                accessParams: {},
                requestParams: {},
                requestMethod: "GET",
                serviceProvider:
                {
                  signatureMethod     : "HMAC-SHA1",
                  requestTokenURL     : "https://www.google.com/accounts/OAuthGetRequestToken",
                  userAuthorizationURL: "https://www.google.com/accounts/OAuthAuthorizeToken",
                  accessTokenURL      : "https://www.google.com/accounts/OAuthGetAccessToken", 
                  echoURL             : ""
                }
            }
        },
        "twitter": function(key, secret) {
            return {
                name: "Twitter",
                version: "1.0",
                consumerKey   : key, 
                consumerSecret: secret,
                token: null,
                tokenSecret: null,
                accessParams: {},
                requestParams: {},
                requestMethod: "GET",
                serviceProvider:
                {
                  signatureMethod     : "HMAC-SHA1",
                  requestTokenURL     : "http://twitter.com/oauth/request_token",
                  userAuthorizationURL: "http://twitter.com/oauth/authorize",
                  accessTokenURL      : "http://twitter.com/oauth/access_token", 
                  echoURL             : ""
                }
            }
        },
        "linkedin": function(key, secret) {
            return {
                name: "LinkedIn",
                version: "1.0",
                consumerKey   : key, 
                consumerSecret: secret,
                token: null,
                tokenSecret: null,
                accessParams: {},
                requestParams: {},
                requestMethod: "GET",
                serviceProvider:
                {
                  signatureMethod     : "HMAC-SHA1",
                  requestTokenURL     : "https://api.linkedin.com/uas/oauth/requestToken",
                  userAuthorizationURL: "https://api.linkedin.com/uas/oauth/authorize",
                  accessTokenURL      : "https://api.linkedin.com/uas/oauth/accessToken", 
                  echoURL             : ""
                }
            }
        },
        "plaxo": function(key, secret) {
            return {
                name: "Plaxo",
                version: "1.0",
                consumerKey   : key, 
                consumerSecret: "", // plaxo doesn't use a secret
                token: null,
                tokenSecret: null,
                accessParams: {},
                requestParams: {},
                requestMethod: "GET",
                serviceProvider:
                {
                  signatureMethod     : "PLAINTEXT",
                  requestTokenURL     : "http://www.plaxo.com/oauth/request",
                  userAuthorizationURL: "http://www.plaxo.com/oauth/authorize",
                  accessTokenURL      : "http://www.plaxo.com/oauth/activate", 
                  echoURL             : ""
                }
            }
        },
        "facebook": function(key, secret) {
            return {
                name: "Facebook",
                version: "2.0",
                consumerKey   : key, 
                consumerSecret: secret,
                token: null,        // access_token
                tokenSecret: null,
                accessParams: {},
                requestParams: {},
                serviceProvider:
                {
                  signatureMethod     : "HMAC-SHA1",
                  userAuthorizationURL: "https://graph.facebook.com/oauth/authorize",
                  accessTokenURL      : "https://graph.facebook.com/oauth/access_token", 
                  echoURL             : ""
                }
            }
        }
        
    };
    
    this.getProvider = function(providerName, key, secret) {
        return this._providers[providerName](key, secret);
    }
    
    this._authorizers = {};
    this.getAuthorizer = function(svc, onCompleteCallback) {
        return new this._authorizers[svc.version](svc, onCompleteCallback);
    }
    
    function OAuth1Handler(oauthSvc, afterAuthorizeCallback) {
        this._log = SimpleLogger.getLogger("oath.authorizer", "oauth.txt", true, true, false);
        this.service = oauthSvc
        this.afterAuthorizeCallback = afterAuthorizeCallback;
    }
    OAuth1Handler.prototype = {
        //starts the authentication process	
        startAuthentication: function()
        {
            this.getRequestToken();
        },

        getRequestToken: function() {
        
            this._log.debug("Getting "+this.service.name+" request token");
        
            var message = {
                method: this.service.requestMethod, 
                action: this.service.serviceProvider.requestTokenURL,
                parameters: this.service.requestParams
            }
            // we fake this big time so we can catch a redirect
            message.parameters['oauth_callback'] = COMPLETION_URI;

            OAuth.completeRequest(message, this.service);
            var requestBody = OAuth.formEncode(message.parameters);
            this._log.debug("REQUEST: "+requestBody);
        
            var call = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                                    .createInstance(Components.interfaces.nsIXMLHttpRequest);
        
            let self = this;
            call.onreadystatechange = function receiveRequestToken() {
                if (call.readyState == 4) {
                    var dump = call.status+" "+call.statusText
                          +"\n\n"+call.getAllResponseHeaders()
                          +"\n"+call.responseText + "\n\n";
                    self._log.debug("Successful call: " + dump);
                    var results = OAuth.decodeForm(call.responseText);
                    let token = OAuth.getParameter(results, "oauth_token");
                    self.getUserAuthorization(results, token);
                }
            };
            call.onerror = function(event) {
                var request = event.target.channel.QueryInterface(Components.interfaces.nsIRequest);
                self._log.debug("got an error!");
            }
            if (message.method == "GET") {
                let targetURL = message.action+"?"+requestBody;
                this._log.debug("REQUEST: "+targetURL);
                call.open(message.method, targetURL, true); 
                call.send(null);
            } else {
                var authorizationHeader = OAuth.getAuthorizationHeader("", message.parameters);
                call.open(message.method, message.action, true); 
                call.setRequestHeader("Authorization", authorizationHeader);
                call.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                call.send(requestBody);
            }
        },

        getUserAuthorization: function(results, token) {
            let self = this;
            let targetURL = this.service.serviceProvider.userAuthorizationURL + "?oauth_token=" + token;
            openOAuthLogin(targetURL,
                           results,
                           function(results, accessToken) {
                                self.getAccessToken(results, accessToken);
                            });
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
              method: this.service.requestMethod, 
              action: this.service.serviceProvider.accessTokenURL,
              parameters: {
                oauth_signature_method: "HMAC-SHA1",
                oauth_verifier: OAuth.decodePercent(accessToken),
                oauth_token   : OAuth.getParameter(requestTokenResults, "oauth_token")
              }
            };
            OAuth.completeRequest(message, this.service);
            var requestBody = OAuth.formEncode(message.parameters);
          
            var call = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                                    .createInstance(Components.interfaces.nsIXMLHttpRequest);
        
            let self = this;
            call.onreadystatechange = function receiveAccessToken() {
                var results = null;
                if (call.readyState == 4) {
                  self._log.debug("Finished getting "+self.service.name+
                                  " request token: " + call.status+" "+call.statusText
                    +"\n"+call.getAllResponseHeaders()+"\n"+call.responseText);
                    
                  results = OAuth.decodeForm(call.responseText);
                  
                  self.service.token = OAuth.getParameter(results, "oauth_token");
                  self.service.tokenSecret = OAuth.getParameter(results, "oauth_token_secret");
                  self.service.access_params = results;
  
                  self.afterAuthorizeCallback(true);
                }
            };
          
            if (message.method == "GET") {
                let targetURL = message.action+"?"+requestBody;
                this._log.debug("REQUEST: "+targetURL);
                call.open(message.method, targetURL, true); 
                call.send(null);
            } else {
                this._log.debug("REQUEST: "+requestBody);
    
                var authorizationHeader = OAuth.getAuthorizationHeader("", message.parameters);
                call.open(message.method, message.action, true); 
                call.setRequestHeader("Authorization", authorizationHeader);
                call.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                call.send(requestBody);
            }
            } catch(e) {
                this._log.error(e);
            }
        }

    };
    this._authorizers["1.0"] = OAuth1Handler;

    function OAuth2Handler(oauthSvc, afterAuthorizeCallback) {
        this._log = SimpleLogger.getLogger("oath.authorizer", "oauth.txt", true, true, false);
        this.service = oauthSvc
        this.afterAuthorizeCallback = afterAuthorizeCallback;
    }
    OAuth2Handler.prototype = {
        startAuthentication: function()
        {
            this.getUserAuthorization();
        },
        getUserAuthorization: function() {
            let self = this;

            var message = {
                method: this.service.requestMethod, 
                action: this.service.serviceProvider.userAuthorizationURL,
                parameters: this.service.requestParams
            }
            // we fake this big time so we can catch a redirect
            message.parameters['redirect_uri'] = COMPLETION_URI;
            message.parameters['client_id'] = this.service.consumerKey;

            var requestBody = OAuth.formEncode(message.parameters);
            let targetURL = message.action + "?" + requestBody;
            this._log.debug("REQUEST: "+targetURL);

            openOAuthLogin(targetURL,
                           null,
                           function(results, accessToken) {
                                self.service.token = accessToken;
                                self.service.access_params = results;
                                self.afterAuthorizeCallback(true);
                            });
        },
        
        // XXX getAccessToken untested
        getAccessToken: function(accessToken)
        {
            this._log.debug("Getting "+this.service.name+" access token: "+accessToken);

            let parameters = this.service.accessParams;
            parameters['code'] = accessToken;
            parameters['callback'] = COMPLETION_URI;
            parameters['client_id'] = this.service.consumerKey;
            parameters['client_secret'] = this.service.consumerSecret;

            var requestBody = OAuth.formEncode(parameters);
            let targetURL = this.service.serviceProvider.accessTokenURL + "?" + requestBody;

            let call = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Components.interfaces.nsIXMLHttpRequest);  
            this._log.debug("REQUEST: "+targetURL);

            let self = this;
            call.open('GET', targetURL, true);
            call.onreadystatechange = function (aEvt) {
                if (call.readyState == 4) {
                    if (call.status == 200) {
                        self._log.debug("Finished getting "+self.service.name+
                                        " request token: " + call.status+" "+call.statusText
                          +"\n"+call.getAllResponseHeaders()+"\n"+call.responseText);
                          
                        results = OAuth.decodeForm(call.responseText);
                        
                        self.service.token = OAuth.getParameter(results, "access_token");
                        self.service.access_params = results;

                        self.afterAuthorizeCallback(true);
                    } else {
                        self._log.error("Unable to access Facebook: error " + call.status + " while getting access token.");
                        dump(call.responseText);
                        self.afterAuthorizeCallback(false);
                    }
                }
            }
            call.send(null);
        }
    }
    this._authorizers["2.0"] = OAuth2Handler;
    
}).call(OAuthConsumer);

