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

### TODO

* Hide tokens from code using OAuthorizer
* Move stored tokens into a secure store (current stored in prefs)
* Make callback uri's unecessary for general use (ie. provide default)
* Make some api's available from web content
* code cleanup, documentation, reviews

## Example use

### Initiating authorization

    Components.utils.import("resource://oauthorizer/modules/oauthconsumer.js");

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

