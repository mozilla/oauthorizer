
try {
Components.utils.import("resource://gre/modules/AddonManager.jsm");
} catch(e) {
  
}

const wpl = Components.interfaces.nsIWebProgressListener;

function closeWindow ()
{
  window.arguments[1].call(null, null);		
  window.close();
}

function doneAuthorizing(oauth_verifier)
{
  window.arguments[1].call(null, oauth_verifier);
  window.close();
}

function openURL(url) {
  let win = window.opener;
  while (win) {
    if (win['openURL']) {
      win.openURL(url);
      break;
    }
    win = win.opener;
  }
}

var reporterListener = {
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
  
  _checkForRedirect: function(aURL) {
      var requestURI = aURL.split('?');
      //dump("change: ["+aURL+"]\n");
      //dump("      : ["+requestURI[0]+"] "+typeof(requestURI[0])+"\n");
      //dump("      : ["+requestURI[1]+"] "+typeof(requestURI[0])+"\n");
      //dump("need: ["+window.arguments[2].completionURI+"] "+typeof(window.arguments[2].completionURI)+"\n");
      //dump(" got? "+(aURL.indexOf(window.arguments[2].completionURI)==0)+"\n");
      //dump(" match? "+(aURL == window.arguments[2].completionURI)+"\n");
      if (aURL.indexOf(window.arguments[2].completionURI) == 0) {
        var oauth_verifier = window.arguments[2].tokenRx.exec(aURL);
        if (oauth_verifier) {
          doneAuthorizing(oauth_verifier[1]);
          return;
        }
      }
  },
  
  QueryInterface: function(aIID) {
    if (aIID.equals(Components.interfaces.nsIWebProgressListener)   ||
        aIID.equals(Components.interfaces.nsIWebProgressListener2)  ||
        aIID.equals(Components.interfaces.nsISupportsWeakReference) ||
        aIID.equals(Components.interfaces.nsISupports))
      return this;
    throw Components.results.NS_NOINTERFACE;
  },
  onStateChange: function(/*in nsIWebProgress*/ aWebProgress,
                     /*in nsIRequest*/ aRequest,
                     /*in unsigned long*/ aStateFlags,
                     /*in nsresult*/ aStatus) {
    if (aStateFlags & wpl.STATE_START &&
        aStateFlags & wpl.STATE_IS_NETWORK) {

      this._checkForRedirect(aRequest.name);

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
      this.statusMeter.value = 0;
      this.statusMeter.parentNode.collapsed = false;
      this.securityLabel.collapsed = true;
    }
    else if (aStateFlags & wpl.STATE_STOP &&
             aStateFlags & wpl.STATE_IS_NETWORK) {
      this.statusMeter.parentNode.collapsed = true;
      this.securityLabel.collapsed = false;
    }
  },

  onProgressChange: function(/*in nsIWebProgress*/ aWebProgress,
                        /*in nsIRequest*/ aRequest,
                        /*in long*/ aCurSelfProgress,
                        /*in long */aMaxSelfProgress,
                        /*in long */aCurTotalProgress,
                        /*in long */aMaxTotalProgress) {
    if (aMaxTotalProgress > 0) {
      let percentage = (aCurTotalProgress * 100) / aMaxTotalProgress;
      this.statusMeter.value = percentage;
    }
  },

  onLocationChange: function(/*in nsIWebProgress*/ aWebProgress,
                        /*in nsIRequest*/ aRequest,
                        /*in nsIURI*/ aLocation) {
    // XXX this needs to be cleaned up to handle differences better, the
    // callback url should be configurable as well
    this.securityDisplay.setAttribute('label', aLocation.host);
    this._checkForRedirect(aLocation.spec);
  },

  onStatusChange: function(/*in nsIWebProgress*/ aWebProgress,
                      /*in nsIRequest*/ aRequest,
                      /*in nsresult*/ aStatus,
                      /*in wstring*/ aMessage) {
  },

  onSecurityChange: function(/*in nsIWebProgress*/ aWebProgress,
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


function loadLoginFrame()
{
  let bundle = document.getElementById("loginBundle");
  var name, desc;
  let svc = window.arguments[2];
  if (svc && svc.extensionID) {
    if (typeof(AddonManager) != 'undefined') {
      AddonManager.getAddonByID(svc.extensionID, function(addon) {
        desc = bundle.getFormattedString('extension.txt',[addon.name, svc.displayName]);
        loadOAuthLoginFrame(desc, svc);
      });
      return;
    } else {
      let ext = Application.extensions.get(svc.extensionID);
      desc = bundle.getFormattedString('extension.txt',[ext.name, svc.displayName]);
    }
  } else {
    name = Application.name;
    desc = bundle.getFormattedString('application.txt',[name, name, svc?svc.displayName:"the interwebs"]);
  }
  loadOAuthLoginFrame(desc, svc);
}

function loadOAuthLoginFrame(desc) {
  let node = document.createTextNode(desc);
  document.getElementById('message').appendChild(node);

  var browser = document.getElementById("oauth_loginFrame");
  browser.addProgressListener(reporterListener, Components.interfaces.nsIWebProgress.NOTIFY_ALL);
  var url = window.arguments[0];
  if (url != "") {
    browser.setAttribute("src", url);
  }
  var app = window.arguments[2].app;
  
}
