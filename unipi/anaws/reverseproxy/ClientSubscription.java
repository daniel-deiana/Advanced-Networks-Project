package it.unipi.anaws.reverseproxy;

import java.util.HashMap;
import java.util.Map;



public class ClientSubscription {
    private static Map<String, Integer> clientsSubscription = null;
    private ClientSubscription() {}
    public static Map<String, Integer> getInstance(){
        if(clientsSubscription == null){
            clientsSubscription = new HashMap<>();
        }

        return clientsSubscription;
    }
}
