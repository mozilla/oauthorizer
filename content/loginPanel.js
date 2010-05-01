
function closeWindow ()
{
  window.arguments[1].call(null, null);		
  window.close();
}

function doneAuthorizing(oauth_verifier)
{
  dump("doneAuthorizing: "+oauth_verifier+"\n");
  window.arguments[1].call(null, oauth_verifier);		
  window.close();
}
              
var reporterListener = {

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
    // XXX this needs to be cleaned up to handle differences better, the
    // callback url should be configurable as well
    dump("onLocationChange: "+aLocation.spec+"\n");
      document.getElementById('security-display').setAttribute('label', aLocation.host);
      if (aLocation.host.indexOf('oauthcallback.local') >= 0) {
        // OAuth 1.0
        var oauth_verifier = /oauth_verifier=([^&]*)/gi.exec(aLocation.spec);
        if (oauth_verifier) {
          dump("***** oauth_verifier: "+oauth_verifier[1]+"\n");
          doneAuthorizing(oauth_verifier[1]);
        }
        // OAuth 2.0
        var oauth_code = /#access_token=([^&]*)/gi.exec(aLocation.spec);
        if (oauth_code) {
          dump("***** oauth_code: "+oauth_code[1]+"\n");
          doneAuthorizing(oauth_code[1]);
        }
      }
    },

  onStatusChange: function(/*in nsIWebProgress*/ aWebProgress,
                      /*in nsIRequest*/ aRequest,
                      /*in nsresult*/ aStatus,
                      /*in wstring*/ aMessage) {
    },

  onSecurityChange: function(/*in nsIWebProgress*/ aWebProgress,
                        /*in nsIRequest*/ aRequest,
                        /*in unsigned long*/ aState) {
    dump("onSecurityChange: ["+aRequest.name+"] state "+aState+"\n");
try {
    const wpl = Components.interfaces.nsIWebProgressListener;
    const wpl_security_bits = wpl.STATE_IS_SECURE |
                              wpl.STATE_IS_BROKEN |
                              wpl.STATE_IS_INSECURE |
                              wpl.STATE_SECURE_HIGH |
                              wpl.STATE_SECURE_MED |
                              wpl.STATE_SECURE_LOW;
    let securityButton = document.getElementById('security-button');
    let securityLabel = document.getElementById('security-status');
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
    dump("security level: "+level+" "+browser.securityUI.tooltipText+"\n")
    if (level) {
      securityButton.setAttribute("level", level);
      securityButton.hidden = false;
      securityLabel.setAttribute("label", browser.securityUI.tooltipText);
    } else {
      securityButton.hidden = true;
      securityButton.removeAttribute("level");
    }
    securityButton.setAttribute("tooltiptext", browser.securityUI.tooltipText);
} catch (e) {
dump(e+"\n");
}
    },
  onProgressChange64: function() {
    dump("onProgressChange64: \n");
    },
  onRefreshAttempted: function() {
    dump("onRefreshAttempted: \n");
    return true; }
}


function loadLoginFrame()
{
  let nsIWebProgress = Components.interfaces.nsIWebProgress;
  var browser = document.getElementById("oauth_loginFrame");
  browser.addProgressListener(reporterListener, nsIWebProgress.NOTIFY_ALL);
  var url = window.arguments[0];
  if (url != "")
    window.setTimeout(function(url) {
          browser.setAttribute("src", url);
    }, 2000, url);
}
