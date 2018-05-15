/*
 
 The simple scanner check class for SHELLING.
 Sends all the payloads one after another, supports time feedback channel only
 
 DNS/HTTP are supported by the CollaboratorScannerCheck class
 
*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.net.URL;
import java.util.Iterator;
import uk.co.pentest.SHELLING.IntruderPayloadGenerator;
import uk.co.pentest.SHELLING.ShellingTab;


public class DirectScannerCheck extends ShellingScannerCheck {

        private ShellingTab tab;	
        
        private List<IScanIssue> issues;        
        private IHttpRequestResponse attackReq;                  
        
	public DirectScannerCheck(IBurpExtenderCallbacks cb, ShellingTab tab) 
        {           
            super(cb,tab);
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
                this.issues = null;
                if(tab.shellingPanel.scannerChecks==false) return this.issues; // the switch
              
                
        	IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
		URL url = reqInfo.getUrl();
                int port = url.getPort();
                String loc="";
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
                
                // create new generator object with a dedicated collaborator subdomain (if DNS used as feedback channel)
                generator = new IntruderPayloadGenerator("cmd", tab, "scanner", baseRequestResponse);  
                // the insertion point should deliver the prefix! to bad intruder can't do this
                
                // save the last generator for the purpose of the asynchronous checkForCollabInteractions() method
                this.tab.shellingPanel.lastGenerator=generator;
                
                // obtain the collaborator domain generated for this one, as we are going to be injecting it in our payloads
                loc = generator.loc;
                
                generator.setBase(baseRequestResponse);
                
                int counter=0;
                while(generator.hasMorePayloads())
                {
                    byte[] payload = generator.getNextPayload(insertionPoint.getBaseValue().getBytes());               
                    // domain name is now automatically provided by the getNextPayload function, used by both scanner and intruder in cooperation with our session tracking system
                    if(payload.length==1) 
                    { //payload generation failed, move onto next command
			callbacks.printError("Payload generation failed!");
			callbacks.issueAlert("Payload generation failed!");
                        return this.issues;
                    }
                    byte [] req = insertionPoint.buildRequest(payload);
                    //callbacks.printError((new String(req))+"\n\n");
                    
                    // feedback channel logic can be coded here, no need for separate checks
                    if(tab.shellingPanel.feedbackChannel=="time")
                    {
                        long millisBefore = System.currentTimeMillis();
                        attackReq = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),req);
                        byte[] resp = attackReq.getResponse();
                        long millisAfter = System.currentTimeMillis();
                        if(millisAfter-millisBefore>25000) // default sleep is 25 seconds, so the difference has to be at least 15 seconds
                        {
                            // raise an issue, abort further checks                        
                            //callbacks.printError(new String(exploitRR.getResponse()));					
                            this.issues = new ArrayList<IScanIssue>(1);			
                            BinaryPayloadIssue issue;
                            issue = new BinaryPayloadIssue(callbacks,attackReq,"");
                            this.issues.add((IScanIssue) issue);
                            return this.issues;
                        }
                    }
                    // filesystem as a feedback channel needs to be implemented too
                    else
                    {
                        counter++;
                        attackReq = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),req);
                        byte[] resp = attackReq.getResponse();
                    
                        if(counter%200==0) // check for feedback every 200 requests
                        {                
                           
                           this.issues=this.tab.shellingPanel.checkCollabInteractions();
                           if(this.issues!=null&&this.issues.size()>0)
                           {
                                this.tab.shellingPanel.logOutput("Returning issues");
                                return this.issues;
                           }
                        }                                                
                    }
                }               
                if(tab.shellingPanel.feedbackChannel=="DNS")
                {
                    try 
                    {   
                	Thread.sleep(20); 
                    } 
                    catch(Exception e) 
                    {
                           // whateva
                    }
                }
                return this.tab.shellingPanel.checkCollabInteractions();
                // check for interactions regardless to the params of this run
                // ideally we should set up a scheduled job (e.g. every 10-15 minutes) to query for incoming collaborator interactions for us
                // but as I don't know how to solve this, let's just make sure to run it with every active scan, intruder attack and on exit
                // currently this will only work from the scanner, unless we figure out how to add custom issues directly by the plugin (instead of returning them from the doActiveScan() handler)
        }	        

} // end of the class
