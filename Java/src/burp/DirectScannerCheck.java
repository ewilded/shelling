/*
 The simple scanner check class for SHELLING.
 Sends all the payloads one after another, supports time feedback channel only

DNS/HTTP are supported by the CollaboratorScannerCheck class

*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.net.URL;
import uk.co.pentest.SHELLING.ShellingTab;


public class DirectScannerCheck extends ShellingScannerCheck {

        private ShellingTab tab;
	public DirectScannerCheck(IBurpExtenderCallbacks cb, ShellingTab tab) 
        {           
            super(cb,tab,"time");
            this.tab = tab;
            checkHttpService = null;
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue) {
		return -1;
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint) 
        {
                List<IScanIssue> issues = null;
                if(tab.shellingPanel.scannerChecks==false) return issues; // the switch
                
                
        	IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
		URL url = reqInfo.getUrl();
                int port = url.getPort();
		boolean https=false;
                String host = url.getHost();
                if(url.getProtocol()=="https") https=true;
		String urlStr = url.getProtocol()+"://"+url.getHost()+":"+url.getPort()+url.getPath();
		if(!createCheckHttpService(host,port,https))  
                {
                    callbacks.printError("HTTP connection failed");
                    callbacks.issueAlert("HTTP connection failed");
                    return issues;
                }
        
                while(generator.hasMorePayloads())
                {
                    byte[] payload = generator.getNextPayload(insertionPoint.getBaseValue().getBytes());               
                    if(payload.length==1) 
                    { //payload generation failed, move onto next command
			callbacks.printError("Payload generation failed!");
			callbacks.issueAlert("Payload generation failed!");
                        return issues;
                    }
                    byte [] req = insertionPoint.buildRequest(payload);
                    //callbacks.printError((new String(req))+"\n\n");
                    long millisBefore = System.currentTimeMillis();
                    IHttpRequestResponse attackReq = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),req);
                    byte[] resp = attackReq.getResponse();
                    long millisAfter = System.currentTimeMillis();
                    if(millisAfter-millisBefore>15000) // default sleep is 15 seconds, so the difference has to be at least 15 seconds
                    {
                        // raise an issue, abort further checks                        
                        //callbacks.printError(new String(exploitRR.getResponse()));					
                        issues = new ArrayList<IScanIssue>(1);			
                        BinaryPayloadIssue issue;
                        issue = new BinaryPayloadIssue(callbacks,attackReq);
                        issues.add((IScanIssue) issue);
                        return issues;
                    }
                }
                return issues;
        }	        

}
