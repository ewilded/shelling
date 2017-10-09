
package burp;

import java.net.URL;
import java.util.Properties;
import java.util.Set;

abstract public class ShellingScannerIssue implements IScanIssue {
	//IScanIssue fields
	private IHttpRequestResponse[] httpMessages;
	private IHttpService httpService;
	private String remediationBackground;
	private URL url;
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	
	private static final String ISSUE_BACKGROUND = "Someone is having a bad day";
	private static final String REM_BACKGROUND = "It's time to play";
	
	ShellingScannerIssue(IBurpExtenderCallbacks cb,IHttpRequestResponse exploitRR) {
		callbacks = cb;
		helpers = callbacks.getHelpers();
		url = helpers.analyzeRequest(exploitRR).getUrl();
		httpService = exploitRR.getHttpService();	
		httpMessages = new IHttpRequestResponse[] {exploitRR};
	}

	
	//IScanIssue methods
	@Override
	public String getConfidence() {
		return "Certain";
	}
	
	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return httpMessages;
	}
	
	@Override
	public IHttpService getHttpService() {
		return httpService;
	}
	
	@Override
	public String getIssueBackground() {
		return ISSUE_BACKGROUND;
	}
	
	@Override
	public abstract String getIssueDetail();
	
	@Override
	public String getIssueName() {
		return "Command Injection (SHELLING)";
	}
	
	@Override
	public int getIssueType() {
		return 0;
	}
	
	@Override
	public String getRemediationBackground() {
		return REM_BACKGROUND;
	}
	
	@Override
	public String getRemediationDetail() {
		return null;
	}
	
	@Override
	public String getSeverity() {
		return "High";
	}
	
	@Override
	public URL getUrl() {
		return url;
	}
}
