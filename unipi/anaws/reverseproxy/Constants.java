package it.unipi.anaws.reverseproxy;

import java.util.Arrays;
import java.util.List;

public class Constants {
    
	// per ora non implementiamo la registrazione dei server quindi gli ip sono hard coded in questo file 
	public static List<String> serversIpList = Arrays.asList("10.0.0.69", "10.0.0.70", "10.0.0.71");
	//public static List<String> serversIpList = Arrays.asList("10.0.0.70");
	public static final String VIRTUAL_IP = "10.0.0.1";
    
}
