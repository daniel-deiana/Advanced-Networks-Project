package it.unipi.anaws.reverseproxy;
import java.util.*;

/*
 * This class is used to store the state of mappings between servers and the clients
 * that they are assigned to
 * */


public class ServerAllocation {
    private ClientServerMapping clientServerMapping = ClientServerMapping.getInstance();

    
    public void handleSubscribe(String ipClient, int k){
        List<String> selectedServers = getLessLoadedServers(k);
        for(String ipServer: selectedServers){
            if (!clientServerMapping.insertMapping(ipClient,ipServer)) {
            	return;
            }
        }
    }
    

    public List<String> getLessLoadedServers(int k) {
        List<Map.Entry<String, List<String>>> l = new ArrayList<>(clientServerMapping.getMappings());
        l.sort(Comparator.comparingInt(entry -> entry.getValue().size()));
        List<String> res = new ArrayList<>();

        for (int i = 0; i < Math.min(k, l.size()); i++) {
            res.add(l.get(i).getKey());
        }
        return res;
    }
}
