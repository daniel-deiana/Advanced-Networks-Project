package it.unipi.anaws.reverseproxy;

import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


/*
 * This class is used to handle the request to the subscribe resource, 
 * it accepts a Json with a given structure (K,client ip)
 * */

public class SubscribeClientResource extends ServerResource {
	@Post("json")
	public String subscribe(String fmJson) {
		String result = new String();
		
		if (fmJson == null) {
			return new String("empty json");
		}
		
		try {
			ObjectMapper mapper = new ObjectMapper();
			JsonNode root = mapper.readTree(fmJson);
			String clientIP = root.get("ClientIP").asText();
			Integer k = root.get("K").asInt();
			
			IReverseProxyREST rest =  (IReverseProxyREST) getContext().getAttributes().get(IReverseProxyREST.class.getCanonicalName());
			result = rest.subscribeClient(clientIP, k);
			
		} catch (Exception e) {
			e.printStackTrace();
		}

		return result;
	}
}