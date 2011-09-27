// Note this was originally used for a custom XUL login Window.
// All references to things like progress and security indicators have
// simply been commented out.

let {Cc, Ci, Cr} = require("chrome");

const wpl = Ci.nsIWebProgressListener;

var reporterListener = function(svc, callback) {
  this.svc = svc;
  this.callback = callback;
}

reporterListener.prototype = {
  _checkForRedirect: function(aURL, aWebProgress) {
      //var requestURI = aURL.split('?');
      //dump("change: ["+aURL+"]\n");
      //dump("      : ["+requestURI[0]+"] "+typeof(requestURI[0])+"\n");
      //dump("      : ["+requestURI[1]+"] "+typeof(requestURI[0])+"\n");
      //dump("need: ["+this.svc.completionURI+"] "+typeof(this.svc.completionURI)+"\n");
      //dump(" got? "+(aURL.indexOf(this.svc.completionURI)==0)+"\n");
      //dump(" match? "+(aURL == this.svc.completionURI)+"\n");
      var oauth_verifier = this.svc.tokenRx.exec(aURL);
      //dump(" rx? "+JSON.stringify(oauth_verifier)+"\n");
      if (oauth_verifier) {
        aWebProgress.removeProgressListener(this);
        this.callback(oauth_verifier[1]);
      }
      if (this.svc.deniedRx.test(aURL)) {
        aWebProgress.removeProgressListener(this);
        this.callback(null);
      }
  },

  QueryInterface: function(aIID) {
    if (aIID.equals(Ci.nsIWebProgressListener)   ||
        aIID.equals(Ci.nsISupportsWeakReference) ||
        aIID.equals(Ci.nsISupports))
      return this;
    throw Cr.NS_NOINTERFACE;
  },
  onStateChange: function(/*in nsIWebProgress*/ aWebProgress,
                     /*in nsIRequest*/ aRequest,
                     /*in unsigned long*/ aStateFlags,
                     /*in nsresult*/ aStatus) {
    if (aStateFlags & wpl.STATE_START &&
        aStateFlags & wpl.STATE_IS_DOCUMENT) { // was STATE_IS_NETWORK, but that doesn't work here...

      this._checkForRedirect(aRequest.name, aWebProgress);
    }
    if (aStateFlags & wpl.STATE_STOP &&
        aStateFlags & wpl.STATE_IS_DOCUMENT) {
      let win = aWebProgress.DOMWindow.window;
      let elt = win.document.documentElement;
      // the scrollWidth etc are still often just a little small for the
      // actual content, so we hard-code a 20% increase.
      win.resizeTo(elt.scrollWidth*1.2, elt.scrollHeight*1.2);
    }
  },

  onProgressChange: function(/*in nsIWebProgress*/ aWebProgress,
                        /*in nsIRequest*/ aRequest,
                        /*in long*/ aCurSelfProgress,
                        /*in long */aMaxSelfProgress,
                        /*in long */aCurTotalProgress,
                        /*in long */aMaxTotalProgress) {
  },

  onLocationChange: function(/*in nsIWebProgress*/ aWebProgress,
                        /*in nsIRequest*/ aRequest,
                        /*in nsIURI*/ aLocation) {
    this._checkForRedirect(aLocation.spec, aWebProgress);
  },

  onStatusChange: function(/*in nsIWebProgress*/ aWebProgress,
                      /*in nsIRequest*/ aRequest,
                      /*in nsresult*/ aStatus,
                      /*in wstring*/ aMessage) {
  },

  onSecurityChange: function(/*in nsIWebProgress*/ aWebProgress,
                        /*in nsIRequest*/ aRequest,
                        /*in unsigned long*/ aState) {
  }
}

exports.listen = function(window, svc, callback) {
  // phew - lots of time went into finding this magic incantation to get an nsIWebProgress for the window...
  let webProgress = window.QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIWebNavigation).QueryInterface(Ci.nsIWebProgress);
  let listener = new reporterListener(svc, callback);
  // seems important to keep a reference to the listener somewhere or
  // notifications stop when the object is GCd.
  webProgress.addProgressListener(listener, Ci.nsIWebProgress.NOTIFY_ALL);
  return listener;
};

exports.stopListening = function(window, listener) {
  let webProgress;
  try {
    webProgress = window.QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIWebNavigation).QueryInterface(Ci.nsIWebProgress);
  } catch (ex) {
    // if the window has been closed we will fail to get the interface
    return;
  }
  webProgress.removeProgressListener(listener);
}
