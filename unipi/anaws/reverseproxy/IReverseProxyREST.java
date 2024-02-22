package it.unipi.anaws.reverseproxy;
import net.floodlightcontroller.core.module.IFloodlightService;



/*
 * Interface for the REST api
 **/

public interface IReverseProxyREST extends IFloodlightService{
	public String subscribeClient (String clientIP, Integer k);
}
