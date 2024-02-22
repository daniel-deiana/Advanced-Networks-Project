from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
 
def create_custom_topology():
	# Create Mininet network
	net = Mininet(controller=RemoteController, switch=OVSSwitch)
 
	# Add controller
	controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
	# Add switches
	upper_switch = net.addSwitch('s1')
	lower_switch1 = net.addSwitch('s2')
	middle_switch = net.addSwitch('s4')
	lower_switch2 = net.addSwitch('s3')
 
	# Add hosts with two subnets
	host1_upper = net.addHost('h1', ip='10.0.0.2/24')
	host2_upper = net.addHost('h2', ip='10.0.0.3/24')
 
	server_host1 = net.addHost('serv1', ip = '10.0.0.70/24')
	server_host2 = net.addHost('serv2', ip = '10.0.0.71/24')
        server_host3 = net.addHost('serv3', ip = '10.0.0.72/24')


	# Connect hosts to switches
	net.addLink(host1_upper, upper_switch)
	net.addLink(host2_upper, upper_switch)
	net.addLink(server_host1, lower_switch1)
	net.addLink(server_host2, lower_switch2)
        net.addLink(server_host3, lower_switch1)

	# Connect switches
	net.addLink(upper_switch, middle_switch)
	net.addLink(middle_switch, lower_switch1)
 
	net.addLink(upper_switch, lower_switch2)
 
	net.start()
 
	# Build the topology
	net.build()
 
	# Enable spanning tree protocol on switches
	upper_switch.cmd('ovs-vsctl set Bridge s1 stp_enable=true')
	lower_switch1.cmd('ovs-vsctl set Bridge s2 stp_enable=true')
	lower_switch2.cmd('ovs-vsctl set Bridge s3 stp_enable=true')
 
	# Open Mininet CLI for testing
	CLI(net)
 
	# Stop Mininet when done
	net.stop()
 
if __name__== '__main__':
	setLogLevel('info')
create_custom_topology()
