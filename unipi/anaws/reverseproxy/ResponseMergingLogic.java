package it.unipi.anaws.reverseproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.OFPort;

import it.unipi.anaws.reverseproxy.ClientSubscription;
import it.unipi.anaws.reverseproxy.Constants;

public class ResponseMergingLogic {
	private final static IPv4Address VIRTUAL_SERVER_IP = IPv4Address.of("10.0.0.254");
	private final static MacAddress VIRTUAL_SERVER_MAC =  MacAddress.of("00:00:00:00:00:FE");
	private Map<String, Integer> responseReceived = new HashMap<>();
    private Map<String, Integer> clientsSubscription = ClientSubscription.getInstance();
    private static ResponseMergingLogic instance = new ResponseMergingLogic();
    
    private ResponseMergingLogic() {}
    
    public static ResponseMergingLogic getInstance() {
    	return instance;
    }
    
    public void insertSubscription(String client, int k) {
    	System.out.println("ip subscribe:"+client);
    	synchronized(responseReceived) {
    		clientsSubscription.put(client, k);
    	}
    }
    
    public boolean receiveServerResponse(IPv4 ipv4Packet, IOFSwitch sw, OFPacketIn pi){
        //byte[] packetData = packet.getData();
        //Ethernet ethPacket = (Ethernet) new Ethernet().deserialize(packetData, 0, packetData.length);
        //IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
        int destIpAddress = ipv4Packet.getDestinationAddress().getInt();
        String clientDest = IPv4.fromIPv4Address(destIpAddress);
        
        int n;
        synchronized(responseReceived) { 
        	n = responseReceived.compute(clientDest, (k, v) -> (v == null) ? 1 : v + 1);
        }
        
        System.out.println("N: "+n);
        System.out.println("K: "+ clientsSubscription.get(clientDest));
        System.out.println("ip retrieve:"+clientDest);
        
        if(n == clientsSubscription.get(clientDest)) {        	
    
            OFActions actions = sw.getOFFactory().actions();
    		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
    		
            OFOxms oxms = sw.getOFFactory().oxms();
            
            
            OFActionSetField setDlSrcRev = actions.buildSetField()
            	    .setField(
            	        oxms.buildEthSrc()
            	        .setValue(VIRTUAL_SERVER_MAC)
            	        .build()
            	    )
            	    .build();
            actionList.add(setDlSrcRev);
            
            OFActionSetField setIpSrcRev = actions.buildSetField()
            	    .setField(
            	        oxms.buildIpv4Src()
            	        .setValue(VIRTUAL_SERVER_IP)
            	        .build()
            	    )
            	    .build();
            actionList.add(setIpSrcRev);
            
            // OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
            
            OFActionOutput.Builder floodActionBuilder = sw.getOFFactory().actions().buildOutput();
            floodActionBuilder.setPort(OFPort.of(2));

            // Aggiunta dell'azione di flooding alla lista delle azioni
            actionList.add(floodActionBuilder.build());
            
    		// Create the Packet-Out and set basic data for it (buffer id and in port)
    		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
    		pob.setBufferId(pi.getBufferId());
    		pob.setInPort(OFPort.ANY);
    		
    		System.out.println("le azioni che ho specificato per il PACKET OUT SONO" + actionList);
    		
    		// Assign the action
    		pob.setActions(actionList);
    		
    		// Packet might be buffered in the switch or encapsulated in Packet-In 
    		// If the packet is encapsulated in Packet-In sent it back
    		if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
    			// Packet-In buffer-id is none, the packet is encapsulated -> send it back
                byte[] packetData = pi.getData();
                pob.setData(packetData);
    		}
    		
    		System.out.println("IL PACKET OUT CHE STO MANDANDO IN RISPOSTA E" + pob.getData());
    		
    		sw.write(pob.build());
        	
            	
        	responseReceived.put(clientDest, 0);
            return true;
        }
        else {
        	return false;
        }
    }
    
    private OFPacketOut createPacketOut(DatapathId switchId, OFPort outPort, byte[] data) {
        OFFactory factory = OFFactories.getFactory(OFVersion.OF_13);
        OFPacketOut.Builder builder = factory.buildPacketOut();
        builder.setBufferId(OFBufferId.NO_BUFFER)
        .setInPort(OFPort.ANY)
        .setActions(Collections.singletonList((OFAction) factory.actions().output(outPort, 0)))
        .setData(data);
        OFPacketOut packetOut = builder.build();
        return packetOut;
    }
}