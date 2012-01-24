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

const {Cc, Ci} = require("chrome");

let {OAuth} = require("./oauth");
let {SimpleLogger} = require("./log4moz");
let {hex_sha1} = require("./sha1");

var OAuthConsumer = exports.OAuthConsumer = {};

(function()
{
    this._log = SimpleLogger.getLogger("oauthconsumer", "oauth.txt", true, true, false);
    this.authWindow = null; // only 1 auth can be happening at a time...

    function makeProvider(name, displayName, key, secret, completionURI, calls, doNotStore) {
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
            tokenRx: /oauth_verifier=([^&]*)/gi,
            deniedRx: /denied=([^&]*)/gi,
            serviceProvider: calls,
            useInternalStorage: !doNotStore
        };
    }
    this.makeProvider = makeProvider;

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
            p.tokenRx = /#access_token=([^&]*)/gi;
            p.deniedRx = /error=access_denied/gi;
            return p;
        }

    };

    this.getProvider = function(providerName, key, secret, completionURI) {
        return this._providers[providerName](key, secret, completionURI);
    }

    function xpath(xmlDoc, xpathString) {
        let root = xmlDoc.ownerDocument == null ?
          xmlDoc.documentElement : xmlDoc.ownerDocument.documentElement;
        let nsResolver = xmlDoc.createNSResolver(root);

        return xmlDoc.evaluate(xpathString, xmlDoc, nsResolver,
                               Ci.nsIDOMXPathResult.ANY_TYPE, null);
    }

    this.discoverProvider = function discoverOAuth(xrds, providerName, displayName, consumerKey, consumerSecret, redirectURL)
    {
        //this._log.debug("requesting OAuth XRD from "+xrds);
        let xrdsResourceLoader = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);
        xrdsResourceLoader.open('GET', xrds, false);
        xrdsResourceLoader.send(null);
        if (xrdsResourceLoader.status != 200) {
            //this._log.warn("OAuth provider XRDS retrieval error (status " + xrdsResourceLoader.status + ")");
            throw {error:"OAuth provider XRDS retrieval error",
                    message:"Communication error with OAuth provider (XRDS retrieval error " + xrdsResourceLoader.status + ")"};
        }
        let xrdsResourceDOM = xrdsResourceLoader.responseXML;

        let self = this;
        function getChildFromResource(dom, type, child) {
            let iter = xpath(xrdsResourceDOM, "//*[local-name()='Service']/*[local-name()='Type' and text()='"+type+"']/../*[local-name()='"+child+"']");
            let elem = iter.iterateNext();
            if (elem == null) {
                self._log.warn("OAuth provider's XRD document has no service element with a type of '"+type+"'");
                throw {error:"OAuths provider's XRD missing PoCo 1.0",  message:"Communication error with OAuth provider (no OAuth service in resource document)"};
            }
            //self._log.debug("    type ["+type+"]=["+elem.textContent+"]");
            return elem.textContent;
        }

        let calls = {
            requestTokenURL:      getChildFromResource(xrdsResourceDOM, 'http://oauth.net/core/1.0/endpoint/request', 'URI'),
            userAuthorizationURL: getChildFromResource(xrdsResourceDOM, 'http://oauth.net/core/1.0/endpoint/authorize', 'URI'),
            accessTokenURL:       getChildFromResource(xrdsResourceDOM, 'http://oauth.net/core/1.0/endpoint/access', 'URI')
        };

        // is this PLAINTEXT or HMAC-SHA1?  We assume that all oauth endpoints use the same.
        let iter = xpath(xrdsResourceDOM, "//*[local-name()='Service']/*[local-name()='URI' and text()='"+calls.requestTokenURL+"']/../*[local-name()='Type']");
        let elem;
        while ((elem = iter.iterateNext())) {
            if (elem) {
                if (elem.textContent == 'http://oauth.net/core/1.0/signature/PLAINTEXT') {
                    calls.signatureMethod = 'PLAINTEXT';
                    break;
                }
                else if (elem.textContent == 'http://oauth.net/core/1.0/signature/HMAC-SHA1') {
                    calls.signatureMethod = 'HMAC-SHA1';
                    break;
                }
            }
        }
        // is it a static consumerKey?
        try {
            consumerKey = getChildFromResource(xrdsResourceDOM,
                                               'http://oauth.net/discovery/1.0/consumer-identity/static',
                                               'LocalID');
            consumerSecret = "";
        } catch(e) {}

        return OAuthConsumer.makeProvider(providerName, displayName, consumerKey, consumerSecret, redirectURL, calls);
    },


    this._authorizers = {};
    this.getAuthorizer = function(svc, onCompleteCallback) {
        return new this._authorizers[svc.version](svc, onCompleteCallback);
    }

    this.__defineGetter__('prefs', function() {
        delete this.prefs;
        let prefService = Cc["@mozilla.org/preferences-service;1"].
                                     getService(Ci.nsIPrefService);
        let extId = module.id;
        return this.prefs = prefService.getBranch("extensions."+extId+".");
    });

    this._makePrefKey = function(providerName, key, secret) {
        return hex_sha1(providerName+":"+key+":"+secret);
    }
    this.resetAccess = function(providerName, key, secret) {
        if (svc.useInternalStorage) {
            key = key || svc.consumerKey;
            secret = secret || svc.consumerSecret;
            let pref = this._makePrefKey(providerName, key, secret);
            this.prefs.setCharPref(pref, "");
        }
    }
    this._setAccess = function(svc) {
        if (svc.useInternalStorage) {
            let key = this._makePrefKey(svc.name, svc.consumerKey, svc.consumerSecret);
            this.prefs.setCharPref(key, JSON.stringify(svc.accessParams));
        }
    }
    this.getAccess = function(svc) {
        if (svc.useInternalStorage) {
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
        } // else svc.accessParams are what is already in the service.
        if (svc.version == "1.0") {
            svc.token = svc.accessParams["oauth_token"];
            svc.tokenSecret = svc.accessParams["oauth_token_secret"];
        }
        else
            svc.token = svc.accessParams["access_token"];
        return svc.token ? true : false;
    }

    function OAuth1Handler(provider, afterAuthorizeCallback) {
        this._log = SimpleLogger.getLogger("oauth.authorizer", "oauth.txt", true, true, false);
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

            //this._log.debug("Getting "+this.service.name+" request token");
            OAuthConsumer.openLoadingDialog();

            var message = {
                method: this.service.requestMethod,
                action: this.service.serviceProvider.requestTokenURL,
                parameters: this.service.requestParams
            }
            // we fake this big time so we can catch a redirect
            message.parameters['oauth_callback'] = this.service.completionURI;
            OAuth.completeRequest(message, this.service);
            var requestBody = OAuth.formEncode(message.parameters);
            //this._log.debug("REQUEST: "+requestBody);

            var call = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"]
                                    .createInstance(Ci.nsIXMLHttpRequest);

            let self = this;
            call.onreadystatechange = function receiveRequestToken() {
                if (call.readyState == 4) {
                    var out = call.status+" "+call.statusText
                          +"\n\n"+call.getAllResponseHeaders()
                          +"\n"+call.responseText + "\n\n";
                    //self._log.debug("Successful call: " + out);
                    var results = OAuth.decodeForm(call.responseText);
                    let token = OAuth.getParameter(results, "oauth_token");
                    self.getUserAuthorization(results, token);
                }
            };
            call.onerror = function(event) {
                var request = event.target.channel.QueryInterface(Ci.nsIRequest);
                self._log.debug("got an error!");
            }
            if (message.method == "GET") {
                let targetURL = message.action+"?"+requestBody;
                //this._log.debug("REQUEST: "+targetURL);
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
            let svc = self.service;
            OAuthConsumer.openDialog(targetURL,
                           results,
                           svc,
                           function(results, accessToken) {
                                if (accessToken) {
                                    self.getAccessToken(results, accessToken);
                                } else {
                                    svc.accessParams = null;
                                    svc.token = null;
                                    svc.tokenSecret = null;
                                    // save into prefs
                                    OAuthConsumer.resetAccess(svc);
                                    self.afterAuthorizeCallback(svc);
                                }
                            });
        },

        _completeAccessRequest: function(message) {
            OAuth.completeRequest(message, this.service);
            var requestBody = OAuth.formEncode(message.parameters);

            var call = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"]
                                    .createInstance(Ci.nsIXMLHttpRequest);

            let self = this;
            call.onreadystatechange = function receiveAccessToken() {
                var results = null;
                if (call.readyState == 4) {
                    if (call.status == 200) {
                        //self._log.debug("Finished getting "+self.service.name+
                        //                " request token: " + call.status+" "+call.statusText
                        //  +"\n"+call.getAllResponseHeaders()+"\n"+call.responseText);

                        results = OAuth.decodeForm(call.responseText);

                        self.service.accessParams = OAuth.getParameterMap(results);
                        self.service.token = self.service.accessParams["oauth_token"];
                        self.service.tokenSecret = self.service.accessParams["oauth_token_secret"];

                        // save into prefs
                        OAuthConsumer._setAccess(self.service);

                        self.afterAuthorizeCallback(self.service);
                    } else {
                        self._log.error("Unable to access "+self.service.name+": error " + call.status + " while getting access token:" + call.responseText);
                        self.afterAuthorizeCallback({error:"API Error", message:"Error while accessing oauth: " + call.status+": "+call.responseText});
                    }
                }
            };

            if (message.method == "GET") {
                let targetURL = message.action+"?"+requestBody;
                //this._log.debug("REQUEST: "+targetURL);
                call.open(message.method, targetURL, true);
                call.send(null);
            } else {
                //this._log.debug("REQUEST: "+requestBody);

                var authorizationHeader = OAuth.getAuthorizationHeader("", message.parameters);
                call.open(message.method, message.action, true);
                call.setRequestHeader("Authorization", authorizationHeader);
                call.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                call.send(requestBody);
            }
        },

        getAccessToken: function(requestTokenResults, accessToken)
        {
            try {
            //this._log.debug("getAccessToken "+this.service.name+
            //                " access token: "+accessToken+" requestToken is " +
            //                JSON.stringify(requestTokenResults));

            this.service.tokenSecret = OAuth.getParameter(requestTokenResults, "oauth_token_secret");
            //this._log.debug("   tokenSecret: "+this.service.tokenSecret)
            let message = {
              method: this.service.requestMethod,
              action: this.service.serviceProvider.accessTokenURL,
              parameters: {
                oauth_signature_method: "HMAC-SHA1",
                oauth_verifier: OAuth.decodePercent(accessToken),
                oauth_token   : OAuth.getParameter(requestTokenResults, "oauth_token")
              }
            };
            this._completeAccessRequest(message);
            } catch(e) {
                this._log.error(e + ": " + e.stack);
            }
        },

        reauthorize: function() {
            let session = this.service.accessParams['oauth_session_handle'];
            //this._log.debug("reauthorize "+this.service.name+
            //                " access token: "+this.service.token+
            //                " oauth_session_handle: " +session);

            let message = {
              method: this.service.requestMethod,
              action: this.service.serviceProvider.accessTokenURL,
              parameters: {
                oauth_signature_method: "HMAC-SHA1",
                oauth_token   : this.service.token,
                oauth_session_handle : session
              }
            };
            this._completeAccessRequest(message);
        }

    };
    this._authorizers["1.0"] = OAuth1Handler;

    /**
     * OAuth2Handler deals with authorization using the OAuth 2.0 protocol.
     * Currently this is only used with Facebook, implementation may be
     * slightly FB specific.
     */
    function OAuth2Handler(oauthSvc, afterAuthorizeCallback) {
        this._log = SimpleLogger.getLogger("oauth.authorizer", "oauth.txt", true, true, false);
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
            //this._log.debug("REQUEST: "+targetURL);

            OAuthConsumer.openDialog(targetURL,
                           null,
                           self.service,
                           function(results, accessToken) {
                                let svc = self.service;
                                if (accessToken) {
                                    svc.token = OAuth.decodePercent(accessToken);
                                    // we don't receive params, save the stuff
                                    // we need
                                    svc.accessParams = {
                                        'access_token': OAuth.decodePercent(accessToken)
                                    };
                                    // save into prefs
                                    OAuthConsumer._setAccess(svc);
                                } else {
                                    svc.token = null;
                                    svc.accessParams = null;
                                    OAuthConsumer.resetAccess(svc);
                                }
                                self.afterAuthorizeCallback(svc);
                            });
        },

        reauthorize: function()
        {
            //this._log.debug("reauthorize "+this.service.name+" access token: "+this.service.token);

            // Facebook specific token format...
            // check expires {secret}.3600.{expires_at_seconds_after_epoch}-{user_id}
            // if we've expired, go through the full user authorization
            let details = /(.*?)\.3600\.(.*?)-(.*)/gi.exec(this.service.token);
            if (details && details[2]) {
                var expires = new Date(details[2] * 1000);
                if (expires < Date.now()) {
                    this.getUserAuthorization();
                    return;
                }
            }

            let parameters = this.service.accessParams;
            parameters['code'] = this.service.token;
            parameters['callback'] = this.service.completionURI;
            parameters['client_id'] = this.service.consumerKey;
            parameters['client_secret'] = this.service.consumerSecret;

            var requestBody = OAuth.formEncode(parameters);
            let targetURL = this.service.serviceProvider.accessTokenURL + "?" + requestBody;

            let call = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);
            //this._log.debug("REQUEST: "+targetURL);

            let self = this;
            call.open('GET', targetURL, true);
            call.onreadystatechange = function (aEvt) {
                if (call.readyState == 4) {
                    if (call.status == 200) {
                        //self._log.debug("Finished getting "+self.service.name+
                        //                " request token: " + call.status+" "+call.statusText
                        //  +"\n"+call.getAllResponseHeaders()+"\n"+call.responseText);

                        results = OAuth.decodeForm(call.responseText);

                        self.service.accessParams = OAuth.getParameterMap(results);
                        self.service.token = self.service.accessParams["access_token"];

                        // save into prefs
                        OAuthConsumer._setAccess(self.service);

                        self.afterAuthorizeCallback(self.service);
                    } else {
                        self._log.error("Unable to access "+self.service.name+": error " + call.status + " while getting access token:" + call.responseText);
                        self.afterAuthorizeCallback({error:"API Error", message:"Error while accessing oauth: " + call.status+": "+call.responseText});
                    }
                }
            }
            call.send(null);
        }
    }
    this._authorizers["2.0"] = OAuth2Handler;

    this._openDialog = function(location) {
        if (this.oauth_listener) {
            require("loginListener").stopListening(this.authWindow, this.oauth_listener);
            this.oauth_listener = null;
        }
        if (this.authWindow && !this.authWindow.closed) {
            // resize to the default size of the window.
            this.authWindow.resizeTo(800, 540);
            this.authWindow.location.href = location;
            this.authWindow.focus();
        } else {
            let wm = Cc["@mozilla.org/appshell/window-mediator;1"]
                               .getService(Ci.nsIWindowMediator);
            let win = wm.getMostRecentWindow(null);
            this.authWindow = win.open(location,
                           "oauth_authorization_dialog",
                           // ideally we would use 'modal', but then we can't get a window ref...
                           "location=yes,centerscreen,dialog=no,width=800,height=540,resizable=yes");
        }
        return this.authWindow;
    }

    this.openLoadingDialog = function() {
        let url = require("self").data.url("content/loading.html");
        this._openDialog(url);
    }

    this.openDialog = function(loginUrl, requestData, svc, afterAuthCallback) {
        let win = this._openDialog(loginUrl);
        var callbackFunc = function(token)
        {
            // no need to stopListening here - if the callback was invoked the
            // listener has already removed itself.
            this.oauth_listener = null;
            this.authWindow.close();
            this.authWindow = null;
            afterAuthCallback(requestData, token);
        }.bind(this);
        this.oauth_listener = require("loginListener").listen(win, svc, callbackFunc);
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
     * @param extensionID   string      extension id
     */
    this.authorize = function(providerName, key, secret, completionURI, callback, params, extensionID) {
        var svc = OAuthConsumer.getProvider(providerName, key, secret, completionURI);
        if (params)
            svc.requestParams = params;
        svc.extensionID = extensionID;
        var handler = OAuthConsumer.getAuthorizer(svc, callback);

        var wm = Cc["@mozilla.org/appshell/window-mediator;1"]
                           .getService(Ci.nsIWindowMediator);
        var win = wm.getMostRecentWindow(null);
        win.setTimeout(function () {
            handler.startAuthentication();
        }, 1);
        return handler;
    }

    function makeURI(aSpec) {
        return Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService).newURI(aSpec, null, null);
    }

    /**
     * call wraps an API call with OAuth data.  You prepare the message, provide
     * a callback and we'll let  you know when we're done.
     *
     * @param svc      object   service object received in the authorize callback
     * @param message  object   message object contains action (url), method (GET|POST) and params (object)
     * @param callback function receives one param, nsIXMLHttpRequest
     */
    this.call = function(svc, message, aCallback) {
        //this._log.debug("OAuth based API call to '"+svc.name+"' at '"+message.action+"'");

        // 1.0 GET: query should contain results of formEncode
        // 1.0 POST: message body should contain non-OAuth parameters only
        // 2.0 GET: query should contain results of formEncode
        // 2.0 POST: message body contains OAuth parameters
        var requestBody;
        if (svc.version == "1.0") {
            if (message.method != "GET") {
                requestBody = OAuth.formEncode(message.parameters);
            }
            message.parameters['oauth_signature_method'] = "HMAC-SHA1";
            message.parameters['oauth_token'] = svc.token;
            OAuth.completeRequest(message, svc);
            if (message.method == "GET"){
                requestBody = OAuth.formEncode(message.parameters); // side effectss
            }
        }
        else if (svc.version == "2.0") {
            message.parameters['access_token'] = svc.token;
            requestBody = OAuth.formEncode(message.parameters);
        }

        let self = this;
        let req = Cc["@mozilla.org/xmlextras/xmlhttprequest;1"].createInstance(Ci.nsIXMLHttpRequest);
        req.onreadystatechange = function OAuthConsumer_call_onreadystatechange(aEvt) {
          if (req.readyState == 4) {
            //self._log.debug("call finished, calling callback");
            aCallback(req);
          }
        }

        if (message.method == "GET") {
            let targetURL = message.action+"?"+requestBody;
            //this._log.debug("GET REQUEST: "+targetURL);
            req.open(message.method, targetURL, true);
            req.send(null);
        } else {
            let realm = makeURI(message.action).host;
            var authorizationHeader = OAuth.getAuthorizationHeader(realm, message.parameters);
            //this._log.debug("" + message.method + " REQUEST: "+message.action + "\nAuthorization: " + authorizationHeader + "\n" + requestBody);
            req.open(message.method, message.action, true);
            req.setRequestHeader("Authorization", authorizationHeader);
            req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            req.send(requestBody);
        }
    }


}).call(OAuthConsumer);
