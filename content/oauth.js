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
* Based on concepts from FireUploader
* The Original Code is OAuthorizer
*
* The Initial Developer of the FireUploader is Rahul Jonna.
* The Initial Developer of the OAuthorizer is Shane Caraveo.
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
Components.utils.import("resource://oauthorizer/modules/sha1.js");

var OAuthConsumer = {};

(function()
{
    var EXT_ID = "oauthorizer@mozillamessaging.com";
    var COMPLETION_URI = "http://oauthcallback.local/access.xhtml";
    this._providers = {
        // while some providers support POST, it seems all providers work
        // with GET, so use GET
        "yahoo": function(key, secret) {
            return {
                name: "yahoo",
                displayName: "Yahoo!",
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
                name: "google",
                displayName: "Google",
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
                name: "twitter",
                displayName: "Twitter",
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
                  requestTokenURL     : "https://twitter.com/oauth/request_token",
                  userAuthorizationURL: "https://twitter.com/oauth/authorize",
                  accessTokenURL      : "https://twitter.com/oauth/access_token", 
                  echoURL             : ""
                }
            }
        },
        "linkedin": function(key, secret) {
            return {
                name: "linkedin",
                displayName: "LinkedIn",
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
                name: "plaxo",
                displayName: "Plaxo",
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
                  requestTokenURL     : "https://www.plaxo.com/oauth/request",
                  userAuthorizationURL: "https://www.plaxo.com/oauth/authorize",
                  accessTokenURL      : "https://www.plaxo.com/oauth/activate", 
                  echoURL             : ""
                }
            }
        },
        "facebook": function(key, secret) {
            return {
                name: "facebook",
                displayName: "Facebook",
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
    
    this._makePrefKey = function(providerName, key, secret) {
        return hex_sha1(providerName+":"+key+":"+secret);
    }
    this.resetAccess = function(providerName, key, secret) {
        let pref = this._makePrefKey(providerName, key, secret);
        Application.extensions.get(EXT_ID).prefs.setValue(pref, "");
    }
    this._setAccess = function(svc) {
        let key = this._makePrefKey(svc.name, svc.consumerKey, svc.consumerSecret);
        Application.extensions.get(EXT_ID).prefs.setValue(key, JSON.stringify(svc.accessParams));
    }
    this._getAccess = function(svc) {
        let key = this._makePrefKey(svc.name, svc.consumerKey, svc.consumerSecret);
        let params = Application.extensions.get(EXT_ID).prefs.getValue(key, null);
        if (!params)
            return false;

        svc.accessParams = JSON.parse(params);
        if (svc.version == "1.0") {
            svc.token = svc.accessParams["oauth_token"];
            svc.tokenSecret = svc.accessParams["oauth_token_secret"];
        }
        else
            svc.token = svc.accessParams["access_token"];
        return svc.token ? true : false;
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
            if (OAuthConsumer._getAccess(this.service))
                this.afterAuthorizeCallback(this.service);
            else
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
            OAuthConsumer.openDialog(targetURL,
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
                  
                  self.service.accessParams = OAuth.getParameterMap(results);
                  self.service.token = self.service.accessParams["oauth_token"];
                  self.service.tokenSecret = self.service.accessParams["oauth_token_secret"];

                  // save into prefs
                  OAuthConsumer._setAccess(self.service);

                  self.afterAuthorizeCallback(self.service);
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
            if (OAuthConsumer._getAccess(this.service))
                this.afterAuthorizeCallback(this.service);
            else
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

            OAuthConsumer.openDialog(targetURL,
                           null,
                           function(results, accessToken) {
                                self.service.token = accessToken;
                                // we don't receive params, save the stuff
                                // we need
                                self.service.accessParams = {
                                    'access_token': accessToken
                                };
                                // save into prefs
                                OAuthConsumer._setAccess(self.service);
                                self.afterAuthorizeCallback(self.service);
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
                        
                        self.service.accessParams = OAuth.getParameterMap(results);
                        self.service.token = self.service.accessParams["access_token"];

                        // save into prefs
                        OAuthConsumer._setAccess(self.service);

                        self.afterAuthorizeCallback(self.service);
                    } else {
                        self._log.error("Unable to access Facebook: error " + call.status + " while getting access token.");
                        dump(call.responseText);
                        self.afterAuthorizeCallback(null);
                    }
                }
            }
            call.send(null);
        }
    }
    this._authorizers["2.0"] = OAuth2Handler;

    this.openDialog = function(loginUrl, requestData, afterAuthCallback) {
        var accessToken = null;
        var callbackFunc = function(token)
        {
            dump("got access token "+token+"\n");
            accessToken = token;
        };

        window.openDialog("chrome://oauthorizer/content/loginPanel.xul",
			  "oauth_authorization_dialog",
			  "chrome,centerscreen,modal,dialog=no",
			  loginUrl, callbackFunc);
        if (accessToken)
        {
            afterAuthCallback(requestData, accessToken);
        }
    }

    /**
     * The one and only API you should use.  Call authorize with your
     * key and secret, your callback will receive a service object that
     * has 3 important members, token, tokenSecret and accessParams.
     * accessParams is an object that contains all the parameters returned
     * during the access request phase of the OAuth protocol.  If you need
     * more than the token or secret (e.g. xoauth_yahoo_guid), look in
     * accessParams.
     *
     * supported providers are at the top of this file.
     */
    this.authorize = function(providerName, key, secret, callback, params) {
        var svc = OAuthConsumer.getProvider(providerName, key, secret);
        if (params)
            svc.requestParams = params;
        var oAuth = OAuthConsumer.getAuthorizer(svc, callback);
        oAuth.startAuthentication(); 
    }

}).call(OAuthConsumer);

