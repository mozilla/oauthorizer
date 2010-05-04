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
let EXPORTED_SYMBOLS = ["OAuthConsumer"];

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");

Components.utils.import("resource://oauthorizer/modules/oauth.js");
Components.utils.import("resource://oauthorizer/modules/Log4Moz.js");
Components.utils.import("resource://oauthorizer/modules/sha1.js");

var OAuthConsumer = {};

(function()
{
    var EXT_ID = "oauthorizer@mozillamessaging.com";
    
    function makeProvider(name, displayName, key, secret, completionURI, calls) {
        return {
            name: name,
            displayName: displayName,
            version: "1.0",
            consumerKey   : key, 
            consumerSecret: secret,
            token: null,       // oauth_token
            tokenSecret: null, // oauth_token_secret
            accessParams: {},  // results from request access
            requestParams: {}, // results from request token
            requestMethod: "GET",
            oauthBase: null,
            completionURI: completionURI,
            serviceProvider: calls
        };
    }

    this._providers = {
        // while some providers support POST, it seems all providers work
        // with GET, so use GET
        "yahoo": function(key, secret, completionURI) {
            let calls = {
                  signatureMethod     : "HMAC-SHA1",
                  requestTokenURL     : "https://api.login.yahoo.com/oauth/v2/get_request_token",
                  userAuthorizationURL: "https://api.login.yahoo.com/oauth/v2/request_auth",
                  accessTokenURL      : "https://api.login.yahoo.com/oauth/v2/get_token"
                };
            return makeProvider('yahoo', 'Yahoo!',
                                     key, secret,
                                     completionURI, calls);
        },
        "google": function(key, secret, completionURI) {
            let calls = {
                  signatureMethod     : "HMAC-SHA1",
                  requestTokenURL     : "https://www.google.com/accounts/OAuthGetRequestToken",
                  userAuthorizationURL: "https://www.google.com/accounts/OAuthAuthorizeToken",
                  accessTokenURL      : "https://www.google.com/accounts/OAuthGetAccessToken"
                };
            return makeProvider('google', 'Google',
                                     key, secret,
                                     completionURI, calls);
        },
        "twitter": function(key, secret, completionURI) {
            let calls = {
                  signatureMethod     : "HMAC-SHA1",
                  requestTokenURL     : "https://twitter.com/oauth/request_token",
                  userAuthorizationURL: "https://twitter.com/oauth/authorize",
                  accessTokenURL      : "https://twitter.com/oauth/access_token"
                };
            return makeProvider('twitter', 'Twitter',
                                     key, secret,
                                     completionURI, calls);
        },
        "linkedin": function(key, secret, completionURI) {
            let calls = {
                  signatureMethod     : "HMAC-SHA1",
                  requestTokenURL     : "https://www.linkedin.com/uas/oauth/requestToken",
                  userAuthorizationURL: "https://www.linkedin.com/uas/oauth/authorize",
                  accessTokenURL      : "https://www.linkedin.com/uas/oauth/accessToken"
                };
            return makeProvider('linkedin', 'LinkedIn',
                                     key, secret,
                                     completionURI, calls);
        },
        "plaxo": function(key, secret, completionURI) {
            let calls = {
                  signatureMethod     : "PLAINTEXT",
                  requestTokenURL     : "https://www.plaxo.com/oauth/request",
                  userAuthorizationURL: "https://www.plaxo.com/oauth/authorize",
                  accessTokenURL      : "https://www.plaxo.com/oauth/activate"
                };
            return makeProvider('plaxo', 'Plaxo',
                                     key, secret,
                                     completionURI, calls);
        },
        "facebook": function(key, secret, completionURI) {
            let calls = {
                  signatureMethod     : "HMAC-SHA1",
                  userAuthorizationURL: "https://graph.facebook.com/oauth/authorize",
                  accessTokenURL      : "https://graph.facebook.com/oauth/access_token"
                };
            let p = makeProvider('facebook', 'Facebook',
                                     key, secret,
                                     completionURI, calls);
            p.version = "2.0";
            return p;
        }
        
    };
    
    this.getProvider = function(providerName, key, secret, completionURI) {
        return this._providers[providerName](key, secret, completionURI);
    }
    
    this._authorizers = {};
    this.getAuthorizer = function(svc, onCompleteCallback) {
        return new this._authorizers[svc.version](svc, onCompleteCallback);
    }
    
    this.__defineGetter__('prefs', function() {
        delete this.prefs;
        let prefService = Components.classes["@mozilla.org/preferences-service;1"].
                                     getService(Components.interfaces.nsIPrefService);
        return this.prefs = prefService.getBranch("extensions."+EXT_ID+".");
    });
    
    this._makePrefKey = function(providerName, key, secret) {
        return hex_sha1(providerName+":"+key+":"+secret);
    }
    this.resetAccess = function(providerName, key, secret) {
        let pref = this._makePrefKey(providerName, key, secret);
        this.prefs.setCharPref(pref, "");
    }
    this._setAccess = function(svc) {
        let key = this._makePrefKey(svc.name, svc.consumerKey, svc.consumerSecret);
        this.prefs.setCharPref(key, JSON.stringify(svc.accessParams));
    }
    this.getAccess = function(svc) {
        let key = this._makePrefKey(svc.name, svc.consumerKey, svc.consumerSecret);
        var params = null;
        try {
            params = this.prefs.getCharPref(key, null);
        } catch(e) {
            return false;
        }
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
    
    function OAuth1Handler(provider, afterAuthorizeCallback) {
        this._log = SimpleLogger.getLogger("oath.authorizer", "oauth.txt", true, true, false);
        this.service = provider;
        this.afterAuthorizeCallback = afterAuthorizeCallback;
    }
    OAuth1Handler.prototype = {
        //starts the authentication process	
        startAuthentication: function()
        {
            if (OAuthConsumer.getAccess(this.service))
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
            message.parameters['oauth_callback'] = this.service.completionURI;
            OAuth.completeRequest(message, this.service);
            var requestBody = OAuth.formEncode(message.parameters);
            this._log.debug("REQUEST: "+requestBody);
        
            var call = Components.classes["@mozilla.org/xmlextras/xmlhttprequest;1"]
                                    .createInstance(Components.interfaces.nsIXMLHttpRequest);
        
            let self = this;
            call.onreadystatechange = function receiveRequestToken() {
                if (call.readyState == 4) {
                    var out = call.status+" "+call.statusText
                          +"\n\n"+call.getAllResponseHeaders()
                          +"\n"+call.responseText + "\n\n";
                    self._log.debug("Successful call: " + out);
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
                           self.service,
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
            let message = {
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
            if (OAuthConsumer.getAccess(this.service))
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
            message.parameters['redirect_uri'] = this.service.completionURI;
            message.parameters['client_id'] = this.service.consumerKey;

            var requestBody = OAuth.formEncode(message.parameters);
            let targetURL = message.action + "?" + requestBody;
            this._log.debug("REQUEST: "+targetURL);

            OAuthConsumer.openDialog(targetURL,
                           null,
                           self.service,
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
        
        reauthorize: function()
        {
            this._log.debug("reauthorize "+this.service.name+" access token: "+this.service.token);

            let parameters = this.service.accessParams;
            parameters['code'] = this.service.token;
            parameters['callback'] = this.service.completionURI;
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
                        self._log.error("Unable to access "+self.service.name+": error " + call.status + " while getting access token.");
                        self.afterAuthorizeCallback(null);
                    }
                }
            }
            call.send(null);
        }
    }
    this._authorizers["2.0"] = OAuth2Handler;

    this.openDialog = function(loginUrl, requestData, svc, afterAuthCallback) {
        var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"]
                           .getService(Components.interfaces.nsIWindowMediator);
        var win = wm.getMostRecentWindow(null);
        var callbackFunc = function(token)
        {
            win.setTimeout(afterAuthCallback, 0, requestData, token);
        };

        win.openDialog("chrome://oauthorizer/content/loginPanel.xul",
			  "oauth_authorization_dialog",
			  "chrome,centerscreen,modal,dialog=no",
			  loginUrl, callbackFunc, svc);
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
     * Some providers require you set a redirection URI when you get your keys,
     * if so, use that same uri for the completionURI param, otherwise, make
     * up a fake uri, such as http://oauthcompletion.local/.  This is used to
     * catch the authorization code automatically.  If it is not provided,
     * oauthorizer will not complete successfully.
     *
     * @param providerName  string      Name of provider
     * @param key           string      api or oauth key from provider
     * @param secret        string      secret key from provider
     * @param completionURI string      redirection URI you configured with the provider
     * @param callback      function    which will recieve one param, the service object
     * @param params        object      extra parmams, such as scope
     * @param extension     object      extIExtension instance, defaults to Application
     */
    this.authorize = function(providerName, key, secret, completionURI, callback, params, extension) {
        var svc = OAuthConsumer.getProvider(providerName, key, secret, completionURI);
        if (params)
            svc.requestParams = params;
        if (typeof(extension) != 'undefined')
            svc.ext = extension;
        var handler = OAuthConsumer.getAuthorizer(svc, callback);

        var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"]
                           .getService(Components.interfaces.nsIWindowMediator);
        var win = wm.getMostRecentWindow(null);
        win.setTimeout(function () {
            handler.startAuthentication();
        }, 1);
        return handler;
    }

}).call(OAuthConsumer);

