/*
 
 The simple scanner check class for SHELLING.
 Sends all the payloads one after another, supports DNS (network) and sleep (time) feedback channels. Will also automatically support "file" once it becomes a thing.

*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.net.URL;
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
                if(tab.shellingPanel.scannerChecks==false) return this.issues; // the switch off (scanner is not enabled, goodbye)
                
                // 
                // We will NO LONGER return scanner issues from this method for DNS and file feedback channels (because they are not direct).
                // doActiveScan() will only return scan issues triggered directly by itself, the current running instance (when using file and time as feedback channels).
                
                // All the DNS interactions (synchronous/asynchronous, does not matter at this point) will be watched by the checkCollabSessions() call (triggered by Scanner/Intruder/Export/exit/schedule?)
                // which will, in turn, will use the addScanIssue() API (with the help of code taken from this useful project https://github.com/PortSwigger/manual-scan-issues).
                
                // Hence, checkCollabInteractions() no longer needs to return issues. We just call it BEFORE starting the actual new scan (this should happen even if the method is again manual, in order not to miss any asynchronously called stuff from previous "auto" calls)
                
                
        	IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
		URL url = reqInfo.getUrl();
                int port = url.getPort();
                String loc="";
                int delaySeconds = this.tab.shellingPanel.getDelay();
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
                if(this.tab.shellingPanel.feedbackChannel=="DNS")
                {
                    this.tab.shellingPanel.lastGenerator=generator;                    
                    // obtain the collaborator domain generated for this one, as we are going to be injecting it in our payloads
                    loc = generator.loc; // this might be empty as we MIGHT be using a different feedback channel
                }                
                generator.setBase(baseRequestResponse);
                
                int counter=0; // we need to limit the frequency with which we are calling the collabSessions check, for the purpose of performance and good manners
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
                    
                    // 1. time as feedback channel (detecting a delay in the response)
                    //if(tab.shellingPanel.feedbackChannel=="time")
                    //{
                    
                    long millisBefore = System.currentTimeMillis(); // only used for time
                    
                    attackReq = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),req); // we perform the attack, because we already know the payload                    
                    byte[] resp = attackReq.getResponse();
                    
                    long millisAfter = System.currentTimeMillis(); // only used for time
                    
                    // Default trigger threshold for "time" feedback channel is 25 seconds, so the difference has to be at least 15 seconds provided that it takes approx. 10 to get a normal response
                    // anyway, made this customisable to anyone encountering false positives with this method.
                    if(this.tab.shellingPanel.feedbackChannel=="time"&&millisAfter-millisBefore>delaySeconds*1000) 
                    {
                            this.issues = new ArrayList<IScanIssue>(1);			
                            BinaryPayloadIssue issue;
                            issue = new BinaryPayloadIssue(callbacks,attackReq,"");
                            this.issues.add((IScanIssue) issue);
                            // return upon the first hit - we should make this adjustable in the config as well
                            return this.issues;
                    }                    
                    
                    // 2. filesystem as a feedback channel needs to be implemented too
                    // if set, it will do nothing here - which is good, as it is up to the user to inspect the filesystem
                    // so far we are good with "time" and "file"
                    // also, "response" will be handled right here once we start supporting it as a feedback channel
                    
                    // now "DNS"
                    
                    // 3. DNS as the feedback channel
                    // So, the point is we do not want to stop sending payloads only because we encountered some collab interaction
                    // as we might be dealing with a response to one of the previous payloads - which is good as we have to report it
                    // but it does not mean we should stop sending payloads unless we can be sure we are dealing with different sessions (different collabLoc).
                    
                    // the check for collab interactions callback run periodically
                    // we could rely entirely on the additional call of this we perform before exiting this method
                    // but the problem is we might get stuck with long scans with the issue staying unnoticed (which would suck soo badly).
                    if(tab.shellingPanel.feedbackChannel=="DNS")
                    {
                        counter++;
                        if(counter%200==0) // check for feedback every 200 requests
                        {                                           
                           this.tab.shellingPanel.checkCollabInteractions(); // just call it and let it do its job (we could provide it with an argument (locId) so it filters
                           // them out for us... but again, we want this to he handled separately, so it can ALSO catch Intruder-induced hits as Scanner issues (yup, that's the point of it)                           
                           //if(this.issues!=null&&this.issues.size()>0)
                           //{                                
                           // we don't return here because we might be finding a response from a previous scan
                           // and we don't want it to stop our CURRENT                                 
                           //}
                        }                                                
                    }
                }
                // OK there is no more payloads left in the generator
                // now would be the good time to save the shellings_raw payload set in the collabSession, if we want to track it
                // and do likewise with Intruder and export (if the "auto" mode is on)
                
                // we are just about to return null
                if(tab.shellingPanel.feedbackChannel=="DNS")
                {
                    try 
                    {   
                	Thread.sleep(10); 
                        this.tab.shellingPanel.checkCollabInteractions(); // one last check after the scan is done
                    } 
                    catch(Exception e) 
                    {
                           // whateva
                    }
                }
                return null;
        }	        
} // end of the class
