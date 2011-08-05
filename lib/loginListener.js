// Note this was originally used for a custom XUL login Window.
// All references to things like progress and security indicators have
// simply been commented out.

let {Cc, Ci, Cr} = require("chrome");

const wpl = Components.interfaces.nsIWebProgressListener;

var reporterListener = function(window, svc, callback) {
  this.window = window;
  this.svc = svc;
  this.callback = callback;
}

reporterListener.prototype = {
/**
  _isBusy: false,
  get statusMeter() {
    delete this.statusMeter;
    return this.statusMeter = document.getElementById("statusbar-icon");
  },
  get securityButton() {
    delete this.securityButton;
    return this.securityButton = document.getElementById("security-button");
  },
  get securityLabel() {
    delete this.securityLabel;
    return this.securityLabel = document.getElementById("security-status");
  },
  get securityDisplay() {
    delete this.securityDisplay;
    return this.securityDisplay = document.getElementById("security-display");
  },
**/
  _checkForRedirect: function(aURL, aWebProgress) {
      //var requestURI = aURL.split('?');
      //dump("change: ["+aURL+"]\n");
      //dump("      : ["+requestURI[0]+"] "+typeof(requestURI[0])+"\n");
      //dump("      : ["+requestURI[1]+"] "+typeof(requestURI[0])+"\n");
      //dump("need: ["+window.arguments[2].completionURI+"] "+typeof(window.arguments[2].completionURI)+"\n");
      //dump(" got? "+(aURL.indexOf(window.arguments[2].completionURI)==0)+"\n");
      //dump(" match? "+(aURL == window.arguments[2].completionURI)+"\n");
      var oauth_verifier = this.svc.tokenRx.exec(aURL);
      if (oauth_verifier) {
        this.callback(oauth_verifier[1]);
        this.window.oauth_listener = null;
        aWebProgress.removeProgressListener(this);
        this.window.close();
      }
  },

  QueryInterface: function(aIID) {
    if (aIID.equals(Ci.nsIWebProgressListener)   ||
        aIID.equals(Ci.nsIWebProgressListener2)  ||
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

      /*
       * As much as I would like to limit on some base url, oauth services
       * do not stick to a single base url all the time, e.g. login with
       * google
       *
      let svc = window.arguments[2];
      dump("requesting: "+aRequest.name+"\n");
      if (aRequest.name.indexOf(svc.oauthBase) != 0 &&
          aRequest.name.indexOf('http://oauthcallback.local/') != 0) {
        // cancel the request, and open in a new tab
        openURL(aRequest.name);
        window.close();
      }
      */
      /*
      this.statusMeter.value = 0;
      this.statusMeter.parentNode.collapsed = false;
      this.securityLabel.collapsed = true;
      */
    }
/**
    else if (aStateFlags & wpl.STATE_STOP &&
             aStateFlags & wpl.STATE_IS_NETWORK) {
      this.statusMeter.parentNode.collapsed = true;
      this.securityLabel.collapsed = false;
    }
***/
  },

  onProgressChange: function(/*in nsIWebProgress*/ aWebProgress,
                        /*in nsIRequest*/ aRequest,
                        /*in long*/ aCurSelfProgress,
                        /*in long */aMaxSelfProgress,
                        /*in long */aCurTotalProgress,
                        /*in long */aMaxTotalProgress) {
    if (aMaxTotalProgress > 0) {
      let percentage = (aCurTotalProgress * 100) / aMaxTotalProgress;
//      this.statusMeter.value = percentage;
    }
  },

  onLocationChange: function(/*in nsIWebProgress*/ aWebProgress,
                        /*in nsIRequest*/ aRequest,
                        /*in nsIURI*/ aLocation) {
    // XXX this needs to be cleaned up to handle differences better, the
    // callback url should be configurable as well
//    this.securityDisplay.setAttribute('label', aLocation.host);
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
  },

  xxx_not_used_onSecurityChange: function(/*in nsIWebProgress*/ aWebProgress,
                        /*in nsIRequest*/ aRequest,
                        /*in unsigned long*/ aState) {
    const wpl_security_bits = wpl.STATE_IS_SECURE |
                              wpl.STATE_IS_BROKEN |
                              wpl.STATE_IS_INSECURE |
                              wpl.STATE_SECURE_HIGH |
                              wpl.STATE_SECURE_MED |
                              wpl.STATE_SECURE_LOW;
    var browser = document.getElementById("oauth_loginFrame");
    var level;

    switch (aState & wpl_security_bits) {
      case wpl.STATE_IS_SECURE | wpl.STATE_SECURE_HIGH:
        level = "high";
        break;
      case wpl.STATE_IS_SECURE | wpl.STATE_SECURE_MED:
      case wpl.STATE_IS_SECURE | wpl.STATE_SECURE_LOW:
        level = "low";
        break;
      case wpl.STATE_IS_BROKEN:
        level = "broken";
        break;
    }
    if (level) {
      this.securityButton.setAttribute("level", level);
      this.securityButton.hidden = false;
      this.securityLabel.setAttribute("label", browser.securityUI.tooltipText);
    } else {
      this.securityButton.hidden = true;
      this.securityButton.removeAttribute("level");
    }
    this.securityButton.setAttribute("tooltiptext", browser.securityUI.tooltipText);
  },
  onProgressChange64: function() {
    return this.onProgressChange(aWebProgress, aRequest,
      aCurSelfProgress, aMaxSelfProgress, aCurTotalProgress,
      aMaxTotalProgress);
  },
  onRefreshAttempted: function() {
    return true;
  }
}

exports.listen = function(window, svc, callback) {
  // phew - lots of time went into finding this magic incantation to get an nsIWebProgress for the window...
  let webProgress = window.QueryInterface(Ci.nsIInterfaceRequestor).getInterface(Ci.nsIWebNavigation).QueryInterface(Ci.nsIWebProgress);
  let listener = new reporterListener(window, svc, callback);
  // seems important to keep a reference to the listener somewhere or
  // notifications stop when the object is GCd.
  window.oauth_listener = listener;
  webProgress.addProgressListener(listener, Ci.nsIWebProgress.NOTIFY_ALL);
};
