package it.unipi.anaws.reverseproxy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

// questa classe implementa il pattern singleton e viene usata dal modulo
// reverse proxy per salvare gli ip dei client associati ad ogni server che
// fa parte del servizio

public class ClientServerMapping {
	
	private static ClientServerMapping instance;
	
	// in teoria il valore di questa mappa dovrebbe essere set cosi da non contenere mai duplicati
	private Map<String, List<String>> mapping;
    
    private ClientServerMapping() {
        mapping = new HashMap<>();
        for (String key : Constants.serversIpList) {
            mapping.put(key, new ArrayList<>());
        }
    }
    
    public static ClientServerMapping getInstance(){
        if(instance == null){	
        	instance = new ClientServerMapping();
        }
        
    	return instance;
    }
    
    
    // meotdo che mi inserrisce un nuovo client nella lista di un determinato server 
    public boolean insertMapping(String clientIP, String serverIP) {
    	
        if (!mapping.containsKey(serverIP)) {
            System.out.println("ServerIP not found in the map: " + serverIP);
            return false;
        }
        List<String> clientList = mapping.get(serverIP);
        // Check if the clientIP is already in the list
        if (clientList.contains(clientIP)) {
            System.out.println("ClientIP already exists in the list for ServerIP: " + serverIP);
            return false;
        }
        
        // Add clientIP to the list
        clientList.add(clientIP);
        return true;
    }
    
    public Set<Map.Entry<String,List<String>>> getMappings() {
    	return mapping.entrySet();
    }
    
    public List<String> getAssignedServers(String client){
    	List<String> res = new ArrayList<>();
    	for(String server: mapping.keySet()) {
    		if(mapping.get(server).contains(client)) {
    			res.add(server);
    		}
    	}
    	
    	return res;
    }
    
}
