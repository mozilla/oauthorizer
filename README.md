# OAuthorizer

The OAuthorizer addon provides a way for chrome code to use OAuth without
needing any knowledge of the details of the OAuth protocol. The only knowledge
required is the OAuth keys and endpoints for initiating the OAuth authorization
process.

### OAuthorizer provides the following functionality:

* Discoverability via XRD if the OAuth provider supports it
* Standard OAuth dialog that wraps the providers authentication and authorization pages
* Chrome code can specify any OAuth provider, or use a set of built-in providers
* Chrome code must provide any OAuth keys necessary for the provider
* A generic mechanism to call any arbitrary OAuth wrapped api call
* OAuth 1 and 2 are supported
* built-in oauth endpoints for Yahoo, Google, Facebook, LinkedIn, Plaxo and Twitter

### TODO

* Hide tokens from code using OAuthorizer
* Move stored tokens into a secure store (current stored in prefs)
* Make callback uri's unecessary for general use (ie. provide default)
* Make some api's available from web content
* Flesh out discovery code
* Consider whether any providers should be built-in, or if the list should be expanded
* code cleanup, documentation, reviews

## Example use

### Initiating authorization

    Components.utils.import("resource://oauthorizer/modules/oauthconsumer.js");

    let provider = 'google'; // just a key name for storing/retrieving data
    let [key, secret, params, completionURI] = [
	    "anonymous",
	    "anonymous",
	    {
	    'xoauth_displayname': "Mozilla Authorizer",
	    'scope': 'http://www.google.com/m8/feeds' 
	    },
	    "http://oauthcallback.local/access.xhtml"
	];
    let svc = null;

    function authorizationCallback(svcObj) {
        dump("*********FINISHED**********\naccess token: "+
             svc.token+"\n  secret: "+svc.tokenSecret+"\n");
        svc = svcObj;
    }
    let handler = OAuthConsumer.authorize(provider, key, secret, completionURI, authorizationCallback, params);


### Making an api call

    let message = {
        action: 'http://www.google.com/m8/feeds/contacts/default/full',
        method: "GET",
        parameters: {'v':'2', "max-results":"2000"}
    };

    // req is an XMLHttpRequest object
    // a more complete example is at
    // https://hg.mozilla.org/labs/people/file/2a4b293fcbe7/modules/importers/gmail.js
    oauthCallback(req) {
        log.info("Google Contacts API: " + req.status+" "+req.statusText);
        // you may need to handle a 401
        if (req.status == 401) {
            var headers = req.getAllResponseHeaders();
            if (req.statusText.indexOf('Token invalid') >= 0)
            {
                // start over with authorization
                OAuthConsumer.resetAccess(svc.name, svc.consumerKey, svc.consumerSecret);
                // have to call OAuthConsumer.authorize
                return;
            }
            else if (headers.indexOf("oauth_problem=\"token_expired\"") > 0)
            {
                handler.reauthorize();
                return;
            }
            // some other error we don't handle
            return;
        }
        
        // everything is good, process the response
    }

    // svc is retreived from the authorize callback above
    OAuthConsumer.call(svc, message, oauthCallback);


### Reset OAuth access

    OAuthConsumer.resetAccess(provider, key, secret);


### Using an OAuth provider that is not built into OAuthorizer

Adding a non-built-in OAuth provider requires a little more knowledge but not
much.  You must always do this once before any other calls into OAuthConsumer if
you are accessing a non-built-in OAuth provider.

    let providerName = 'yahoo';
    let secret = "My Consumer Secret";
    let key = "My Consumer Key";
    let calls = {
          signatureMethod     : "HMAC-SHA1",
          requestTokenURL     : "https://api.login.yahoo.com/oauth/v2/get_request_token",
          userAuthorizationURL: "https://api.login.yahoo.com/oauth/v2/request_auth",
          accessTokenURL      : "https://api.login.yahoo.com/oauth/v2/get_token"
        };
    let myprovider = OAuthConsumer.makeProvider(providerName, 'Yahoo!',
                                                key, secret,
                                                completionURI, calls);
    // XXX should be handled internally by makeProvider
    OAuthConsumer._providers[providerName] = myprovider;


#### Configuring an OAuth provider via XRD

XXX Discovery is simplistic, probably doesn't work 100%.

    OAuthConsumer.discoverProvider(xrdsURI, providerName, displayName,
                                   consumerKey, consumerSecret, redirectURL)


