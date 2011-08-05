// This script is injected into tester.html to expose an API it can use.

// A stub around the OAuthConsumer classes - just enough to get the tester working.
function OAuthConsumer() {
    ;
};

OAuthConsumer.prototype = {
    authorize: function(provider, key, secret, completionURI, callback, params) {
        self.port.once("authorize_result", function(result) {
            callback(result);
        });
        self.port.emit("authorize", {provider: provider, key: key, secret: secret, completionURI: completionURI, params: params});
    },

    resetAccess: function(provider, key, secret) {
        self.port.emit("resetAccess", {provider: provider, key: key, secret: secret});
    }
};

unsafeWindow.OAuthConsumer = new OAuthConsumer();
