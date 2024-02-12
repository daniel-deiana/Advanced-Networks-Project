package it.unipi.anaws.reverseproxy;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFValueType;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.util.HexString;
import org.restlet.routing.Route;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.NodePortTuple;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Path;
import net.floodlightcontroller.util.FlowModUtils;

public class ReverseProxy implements IOFMessageListener, IFloodlightModule, IReverseProxyREST {
	
	// servizi da aggiungere
	// - servizio device (per ottenere gli attachment point)
	// - servizio routing (per ottenere la lista di switch)
	
	private static final int IDLE_TIMEOUT = 0;
	private static final int HARD_TIMEOUT = 0;
	private final static IPv4Address VIRTUAL_SERVER_IP = IPv4Address.of("10.0.0.254");
	private final static MacAddress VIRTUAL_SERVER_MAC =  MacAddress.of("00:00:00:00:00:FE");
	
	protected IOFSwitchService switchService;
	protected IRoutingService routingService;
	protected IRestApiService restApiService;
	protected IFloodlightProviderService floodlightProvider;
	protected IDeviceService deviceService;
	protected static Logger log;

	// Reverse proxy data structures 
	private static Map<String, Integer> registeredClients = new HashMap<>();
	
	// /////////////////////////////////////////////////////////////////////////////////////////////////////
	// /////////////////////////////////////////////////////////////////////////////////////////////////////
	// Base methods
	
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return ReverseProxy.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = 
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IReverseProxyREST.class); 
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = 
				new HashMap<Class<? extends IFloodlightService>, IFloodlightService>(); 
		m.put(IReverseProxyREST.class, this); 
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// adding the dependencies for the module
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(IRoutingService.class);
		l.add(IOFSwitchService.class);
		l.add(IRestApiService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// retrieve the reference to the floodlight provider
		// initialize api service


		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		routingService = context.getServiceImpl(IRoutingService.class);
		deviceService = context.getServiceImpl(IDeviceService.class);
		restApiService = context.getServiceImpl(IRestApiService.class);
		switchService = context.getServiceImpl(IOFSwitchService.class);
		log = LoggerFactory.getLogger(ReverseProxy.class);

	}
	
	
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		restApiService.addRestletRoutable(new ReverseProxyWebRoutable());
	}

	
	/*
	 * (non-Javadoc)
	 * @see net.floodlightcontroller.core.IOFMessageListener#receive(net.floodlightcontroller.core.IOFSwitch, org.projectfloodlight.openflow.protocol.OFMessage, net.floodlightcontroller.core.FloodlightContext)
	 */
	
	// /////////////////////////////////////////////////////////////////////////////////////////////////////
	// ////////////////////////////////////////////////////////////////////////////////////////////////////
	// Application logic methods 
	
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {	
		// System.out.println("il dpid dello switch a cui" + targetIpAddress + "e connesso = " + clientDevice.toString());
		
		// qua devo controllare se il sorgente sia un ip di uno dei server, se lo e'
		// allora devo aggiornare la struttura dati che mi tiene conto delle richieste pendenti
		// se trovo che ho ricevuto tutte le risposte allora inoltro allo switch che mi ha mandato
		// il packet il pacchetto di partenza, cambiando solamente src_ip e src_mac in quelli del server virtuale
		
		// se il sorgente non fa parte di quello dei server allora qua devo gestire sta situazione 
		// possibilmente non dovrei fare niente
		
		// la richiesta comunque mi genera un packet_in, quindi devo controllare se l indirizzo ip sorgente puo essere
		// di uno dei client perche io poi devo generare k pacchetti da inoltrare poi nella rete, questi k pacchetti devo avere
		// destinazioni diverse, una volta fatto questo possono viaggiare tranquillamente attraverso la rete 
		
		

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		IPacket pkt = eth.getPayload();
		
		OFPacketIn pi = (OFPacketIn) msg;
		
		if (eth.isBroadcast() || eth.isMulticast()) {
			if (pkt instanceof ARP) {
				ARP arpRequest = (ARP) eth.getPayload();		
				if( arpRequest.getTargetProtocolAddress().compareTo(VIRTUAL_SERVER_IP) == 0 ){
				
					System.out.printf("Processing ARP request\n");
					// Process ARP request
					handleARPRequest(sw, pi, cntx);
					
					// Interrupt the chain
					return Command.STOP;
				}
			}
		}  else if (pkt instanceof IPv4) {
		    IPv4 ip_pkt = (IPv4) pkt;
		        
		    System.out.println("PROTOCOLLO " + ip_pkt.getProtocol());
		    
		    if(ip_pkt.getProtocol().getIpProtocolNumber() == 1) { 
		    	
		    	 System.out.println("PROTOCOLLO ICMP" );
		    	return Command.CONTINUE;
		    }
		    
		    // Il pacchetto non è ICMP, gestiscilo come un normale pacchetto IP
		    handleIPPacket(sw, pi, cntx);
		    return Command.STOP;
		}
		
		return Command.CONTINUE;
	}

	@Override
	public String subscribeClient(String clientIP, Integer k) {
				
		ResponseMergingLogic.getInstance().insertSubscription(clientIP);
			
		ServerAllocation allocationManager = new ServerAllocation();
		allocationManager.handleSubscribe(clientIP,k);
		ClientServerMapping mappings = ClientServerMapping.getInstance();

		System.out.println("Inserted new clients " + mappings.getMappings());
		
		
		// TEST
		System.out.println("Assigned servers: "+ClientServerMapping.getInstance().getAssignedServers(clientIP));
		
		List<String> assignedServers = ClientServerMapping.getInstance().getAssignedServers(clientIP);
		
		for (String serverIp: assignedServers) {
			
			try {
			setDirectPath(clientIP,serverIp);
			setReversePath(clientIP,serverIp);
			} catch (Exception e) {
				return "SUBSCRIPTION FALLITA";
			}
		}
		
		
		// TESTING 
		// qua assegni i vari server al client e poi mi printi i server che hai assegnato
		// ClientServerMapping clientServerMapping = ClientServerMapping.getInstance();
		// clientServerMapping.insertMapping(clientIP, "10.0.0.69");
		
		
		// qua invece mi fai il setup della direct e reverse path per ogni server che hai associato
		// al client 
		
		// cicli per ogni server assegnato e crei le path
		
		// nella path diretta va matchato il pacchetto con | ip_client | ip_server | --> azione: inoltro del pacchetto su una delle porte di quel path
		
		
		// log.debug("LOG: Inserted new client" + clientServerMapping.getMappings());
		
	
		
		return "SUBSCRIBE COMPLETATA, SERVER ASSEGNATI: " + assignedServers;
	}
	
	
	
	// funzione di utilita che mi ritorna un oggetto device passando come argomento il suo ip
	public IDevice getDeviceByIpAddress(String address) {
		Collection<? extends IDevice> devices = deviceService.getAllDevices();
		
		System.out.println("DEVICES SONO" + devices);
		
		for (IDevice device : devices) {
			if(device.getIPv4Addresses().length != 0  && device.getIPv4Addresses()[0].toString().equals(address)) {
				return device;
			}
		}
		return null;
	}
	
	public void setDirectPath(String clientAddress, String serverAddress) {

		String clientIpAddress = IPv4Address.of(clientAddress).toString();	
		String serverIpAddress = IPv4Address.of(serverAddress).toString();
	

		IDevice clientDevice = getDeviceByIpAddress(clientIpAddress);
		IDevice serverDevice = getDeviceByIpAddress(serverIpAddress);

		DatapathId serverSwDPID = serverDevice.getAttachmentPoints()[0].getNodeId();
		DatapathId clientSwDPID = clientDevice.getAttachmentPoints()[0].getNodeId();		                                                           
		
		Path path = routingService.getPath(clientSwDPID,serverSwDPID);

		System.out.println("la DIRECT path da AB e'" + path + " FINE PATH");
		
		for (int i = 0; i < path.getPath().size(); i++) {
			
			System.out.println("sono all iterazione" + i);
			
			NodePortTuple hopInfoA = path.getPath().get(i);
			
			// ottengo sw e porta del src e del destinatario, considerando l hop corrente A ---> B
			DatapathId srcSw = hopInfoA.getNodeId();
			OFPort srcPort = hopInfoA.getPortId();
							
			IOFSwitch targetSw = switchService.getSwitch(srcSw);
			// creazione della regola diretta 
			
			OFFlowAdd.Builder fmb = targetSw.getOFFactory().buildFlowAdd();
			
	        fmb.setIdleTimeout(IDLE_TIMEOUT);
	        fmb.setHardTimeout(HARD_TIMEOUT);
	        fmb.setBufferId(OFBufferId.NO_BUFFER);
	        fmb.setOutPort(OFPort.ANY);
	        fmb.setPriority(FlowModUtils.PRIORITY_MAX);
	        
	        // actions 
	        OFActions actions = targetSw.getOFFactory().actions();
	        // Create the actions (Change DST mac and IP addresses and set the out-port)
	        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        
	        OFOxms oxms = targetSw.getOFFactory().oxms();
	        Match.Builder mb = targetSw.getOFFactory().buildMatch();
	        
	        // sono nel primo switch
	       
        	// Il match per il primo switch si fa con l ip virtuale e il mac virtuale
	        mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
	        .setExact(MatchField.ETH_SRC, clientDevice.getMACAddress())
	        .setExact(MatchField.IPV4_SRC, clientDevice.getIPv4Addresses()[0])
	        .setExact(MatchField.IPV4_DST,serverDevice.getIPv4Addresses()[0] )
	        .setExact(MatchField.ETH_DST, serverDevice.getMACAddress());
	        
	        // le azioni che vengono fatte al primo switch sono quelle di cambiare mac e ip destinazione 
	        // con uno dei server assegnati		        
	        
	        srcPort = (i == path.getPath().size() - 1) ? serverDevice.getAttachmentPoints()[0].getPortId() : srcPort;
	        
	        OFActionOutput output = actions.buildOutput()
	        	    .setMaxLen(0xFFffFFff)
	        	    .setPort(srcPort)
	        	    .build();
	        actionList.add(output);
	        	        
	        // scrivi le azioni ed i match nel messaggio flow mod
	        fmb.setActions(actionList);
	        fmb.setMatch(mb.build());

	        // OTTIENI LO SWITCH DALLA DATAPATHID DEL DEVICE
	        targetSw.write(fmb.build());
		}

	}
	
	public void setReversePath(String clientAddress,String serverAddress) {

		String clientIpAddress = IPv4Address.of(clientAddress).toString();	
		String serverIpAddress = IPv4Address.of(serverAddress).toString();
	

		IDevice clientDevice = getDeviceByIpAddress(clientIpAddress);
		IDevice serverDevice = getDeviceByIpAddress(serverIpAddress);

		DatapathId serverSwDPID = serverDevice.getAttachmentPoints()[0].getNodeId();
		DatapathId clientSwDPID = clientDevice.getAttachmentPoints()[0].getNodeId();		                                                           
		
		Path path = routingService.getPath(serverSwDPID, clientSwDPID);

		System.out.println("la path REVERSE da AB e'" + path + " FINE PATH");
		
		for (int i = 0; i < path.getPath().size(); i++) {
			
			System.out.println("sono all iterazione" + i);
			
			NodePortTuple hopInfoA = path.getPath().get(i);
			
			// ottengo sw e porta del src e del destinatario, considerando l hop corrente A ---> B
			DatapathId srcSw = hopInfoA.getNodeId();
			OFPort srcPort = hopInfoA.getPortId();
							
			IOFSwitch targetSw = switchService.getSwitch(srcSw);
			// creazione della regola diretta 
			
			OFFlowAdd.Builder fmb = targetSw.getOFFactory().buildFlowAdd();
			
	        fmb.setIdleTimeout(IDLE_TIMEOUT);
	        fmb.setHardTimeout(HARD_TIMEOUT);
	        fmb.setBufferId(OFBufferId.NO_BUFFER);
	        fmb.setOutPort(OFPort.ANY);
	        fmb.setPriority(FlowModUtils.PRIORITY_MAX);
	        
	        // actions 
	        OFActions actions = targetSw.getOFFactory().actions();
	        // Create the actions (Change DST mac and IP addresses and set the out-port)
	        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        
	        Match.Builder mb = targetSw.getOFFactory().buildMatch();
	                	
        	// regole che installo sugli switch successivi
	        mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
	        .setExact(MatchField.ETH_SRC, VIRTUAL_SERVER_MAC)
	        .setExact(MatchField.IPV4_SRC, VIRTUAL_SERVER_IP)
	        .setExact(MatchField.IPV4_DST, clientDevice.getIPv4Addresses()[0])
	        .setExact(MatchField.ETH_DST, clientDevice.getMACAddress());	
	        
	        
	        srcPort = (i == path.getPath().size() - 1) ? clientDevice.getAttachmentPoints()[0].getPortId() : srcPort;
	        
	        OFActionOutput output = actions.buildOutput()
	        	    .setMaxLen(0xFFffFFff)
	        	    .setPort(srcPort)
	        	    .build();
	        actionList.add(output);
	        
        
	        // scrivi le azioni ed i match nel messaggio flow mod
	        fmb.setActions(actionList);
	        fmb.setMatch(mb.build());

	        // OTTIENI LO SWITCH DALLA DATAPATHID DEL DEVICE
	        targetSw.write(fmb.build());
		}
	}
	
	private void handleARPRequest(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {

		// Double check that the payload is ARP
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof ARP))
			return;
		
		// Cast the ARP request
		ARP arpRequest = (ARP) eth.getPayload();
		// Generate ARP reply
		IPacket arpReply = new Ethernet()
			.setSourceMACAddress(VIRTUAL_SERVER_MAC)
			.setDestinationMACAddress(eth.getSourceMACAddress())
			.setEtherType(EthType.ARP)
			.setPriorityCode(eth.getPriorityCode())
			.setPayload(
				new ARP()
				.setHardwareType(ARP.HW_TYPE_ETHERNET)
				.setProtocolType(ARP.PROTO_TYPE_IP)
				.setHardwareAddressLength((byte) 6)
				.setProtocolAddressLength((byte) 4)
				.setOpCode(ARP.OP_REPLY)
				.setSenderHardwareAddress(VIRTUAL_SERVER_MAC) // Set my MAC address
				.setSenderProtocolAddress(VIRTUAL_SERVER_IP) // Set my IP address
				.setTargetHardwareAddress(arpRequest.getSenderHardwareAddress())
				.setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));
				
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
		
		
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
		OFPort inPort =  pi.getMatch().get(MatchField.IN_PORT);
		
		System.out.println("LA PORTA A CUI STO RIMANANDO E " + inPort);
		
        actionBuilder.setPort(inPort);  
		
		// Assign the action
		pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		
		// Set the ARP reply as packet data 
		byte[] packetData = arpReply.serialize();
		pob.setData(packetData);
		
		System.out.printf("Sending out ARP reply\n");
		
		sw.write(pob.build());
	}
	
	private void handleIPPacket(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {

		// Double check that the payload is IPv4
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (! (eth.getPayload() instanceof IPv4))
			return;
		
		// Cast the IP packet
		IPv4 ipv4 = (IPv4) eth.getPayload();
		
		/*if(!ipv4.getSourceAddress().equals(IPv4Address.of("10.0.0.70"))) {
			return;
		}*/
			
		System.out.printf("Processing IPv4 packet\n");
		System.out.printf("il pacchetto che sto analizzando proviene da " + ipv4.getSourceAddress() + "diretto ad " + ipv4.getDestinationAddress());
		
		// se il pacchetto arriva da uno dei server
		if(Constants.serversIpList.contains(ipv4.getSourceAddress().toString())) {
			System.out.printf("Pacchetto dal server\n");
			// se non è l'ultima risposta che deve arrivare
			if(!ResponseMergingLogic.getInstance().receiveServerResponse(ipv4,sw,pi)) {
				// drop the packet
				return;
			}
		}
		else if (ipv4.getDestinationAddress().equals(VIRTUAL_SERVER_IP)) {
	
			sendPacketReplicates(sw,ipv4,pi,cntx);
		}
	}
	
	public void sendPacketReplicates(IOFSwitch sw, IPv4 ipv4, OFPacketIn pi , FloodlightContext cntx) {
		
		List<String> targetServers = ClientServerMapping.getInstance().getAssignedServers(ipv4.getSourceAddress().toString());
		System.out.println("SONO NELLA HANDLE IP; I PACCHETTI ASSEGNATI " + targetServers);
		
		
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (! (eth.getPayload() instanceof IPv4))
			return;
		
		for(String serverIp: targetServers) {
			
			IDevice targetServer = getDeviceByIpAddress(serverIp);
		
		
	        OFActions actions = sw.getOFFactory().actions();
			ArrayList<OFAction> actionList = new ArrayList<OFAction>();
			

	        OFOxms oxms = sw.getOFFactory().oxms();
			
	        OFActionSetField setDlDst = actions.buildSetField()
	        	    .setField(
	        	        oxms.buildEthDst()
	        	        .setValue(targetServer.getMACAddress())
	        	        .build()
	        	    )
	        	    .build();
	        actionList.add(setDlDst);
	        
	        
	        OFActionSetField setIpDst = actions.buildSetField()
	        	    .setField(
	        	        oxms.buildIpv4Dst()
	        	        .setValue(targetServer.getIPv4Addresses()[0])
	        	        .build()
	        	    )
	        	    .build();
	        actionList.add(setIpDst);
	 
	        
	        
			OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
			// The method to retrieve the InPort depends on the protocol version 
			OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
			
			// spedisci sulla porta di uscita per il percorso 
			
			// --------------
			IDevice clientDevice = getDeviceByIpAddress(ipv4.getSourceAddress().toString());

			DatapathId serverSwDPID = targetServer.getAttachmentPoints()[0].getNodeId();
			DatapathId clientSwDPID = clientDevice.getAttachmentPoints()[0].getNodeId();		                                                           
			
			Path path = routingService.getPath(clientSwDPID,serverSwDPID);
			
			actionBuilder.setPort(path.getPath().get(0).getPortId()); 
	        // ----------------
			
			actionList.add(actionBuilder.build());
	        
			
			System.out.println("le azioni che ho specificato per il PACKET OUT RIFERITO AL SERVER "+ targetServer.getIPv4Addresses()[0].toString() +"DELLA SEND REPLICATES SONO" + actionList);
			
	    	// Create the Packet-Out and set basic data for it (buffer id and in port)
			OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
			pob.setBufferId(pi.getBufferId());
			pob.setInPort(OFPort.ANY);
			pob.setActions(actionList);
			
	        
			if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
				// Packet-In buffer-id is none, the packet is encapsulated -> send it back
	            byte[] packetData = pi.getData();
	            pob.setData(packetData);
			} 
			
			sw.write(pob.build());
	}
}
}
