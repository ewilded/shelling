
package burp;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.net.URL;
import uk.co.pentest.SHELLING.ShellingTab;


public class CollaboratorScannerCheck extends ShellingScannerCheck {
	private IBurpCollaboratorClientContext collabClient;
	private ShellingTab tab;
        private String collabLoc;
        private List<IBurpCollaboratorInteraction> collabInter;
        private List<IScanIssue> issues;
        private IHttpRequestResponse base;
        
        private IBurpCollaboratorInteraction inter;
        private Iterator<IBurpCollaboratorInteraction> collabInterItr;
                
	public CollaboratorScannerCheck(IBurpExtenderCallbacks cb, ShellingTab tab) {
		super(cb, tab, "DNS");
                this.tab=tab;
		collabClient = callbacks.createBurpCollaboratorClientContext();
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue) {
		return -1;
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint) {
		
                this.issues = null;
                this.base = baseRequestResponse;
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
                
                collabLoc = collabClient.generatePayload(true);
                inter = null;				
                collabInterItr = null;
                
                int counter=0;
                while(generator.hasMorePayloads())
                {
                    counter++;
                    byte[] payload = generator.getNextPayload(insertionPoint.getBaseValue().getBytes());               
                    if(payload.length==1) 
                    { //payload generation failed, move onto next command
			callbacks.printError("Payload generation failed!");
			callbacks.issueAlert("Payload generation failed!");
                        return issues;
                    }
                    byte [] req = insertionPoint.buildRequest(payload);
                    //callbacks.printError((new String(req))+"\n\n");

                    IHttpRequestResponse attackReq = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),req);
                    byte[] resp = attackReq.getResponse();
                    
                    if(counter%200==0&&checkCollabInteractions()) // check for feedback every 200 requests
                    {                        
                        // raise an issue, abort further checks                        
                        //callbacks.printError(new String(exploitRR.getResponse()));					
                        return issues;
                    }
                }
                try 
                {
                	Thread.sleep(60); // the question is what is the safe wait time here (not assuming to catch non-synchronous occurrences here - which is bollocks, by the way, has to be sorted as well)
                } 
                catch(Exception e) 
                {
                        // whateva
                }
                checkCollabInteractions(); // check for feedback once again
                return this.issues;
            
	}       
        private boolean checkCollabInteractions()
        {
           // only DNS interactions are supported at the moment
           collabInter = collabClient.fetchCollaboratorInteractionsFor(collabLoc);
           
           if(collabInter.size()>0) 
           { 
                //if interaction(s) were found from the current poll request, add all to overall list and continue
                collabInterItr = collabInter.iterator();
                // only reading one, first interaction (at least now)
                inter = collabInterItr.next();
                
 	        issues = new ArrayList<IScanIssue>(1);			
                // This method is used to retrieve a property of the interaction. 
                // Properties of all interactions are: interaction_id, type, client_ip, and time_stamp. 
                // Properties of DNS interactions are: query_type and raw_query. The raw_query value is Base64-encoded. 
                // Properties of HTTP interactions are: protocol, request, and response. 
                // The request and response values are Base64-encoded
                
        	byte[] collabQyery = helpers.base64Decode(inter.getProperty("raw_query"));
                // now: bytes to string, extract the index number, ask the generator for the payload, build the issue object                
                // OK, now we need to obtain the DNS domain name catched by the collab server
                // and then use it to track the request/payload number we used for the attack
                // storing shitloads of requests in an array is not optimum, payload index should be sufficient
                // as all we need is the golden payload anyway
                issues.add((IScanIssue) new BinaryPayloadIssue(callbacks,base)); 
                return true;
            }
            return false;
        }
}
