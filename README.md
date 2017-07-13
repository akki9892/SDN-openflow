# SDN-openflow
Software define network configuration using RYU.
OpenFlow, an instance of the SDN architecture, is a set of specifications maintained by the Open Networking Forum (ONF). At the core of the specifications is a definition of an abstract packet processing machine, called a switch. The switch processes packets using a combination of packet contents and switch configuration state. A protocol is defined for manipulating the switch's configuration state as well as receiving certain switch events. Finally, a controller is an element that speaks the protocol to manage the configuration state of many switches and respond to events. 
This project aims at creating the software define network using the openflow protocol with HP-2920 switches and Dell power edge R430 and R530 controller. Furture the project aims at displaying the topology on GUI,creating flows,deleting flows,modifying flows.
The controller is connected to all the switches through vlan 192(control plane) 192.168.0.0 network.
All the switches are connected to each other with vlan 10(Data plane) 20.0.0.0 network.
All the switch has the version 15.5
To see the topology and establish the connection between the controller and the switches
./ryu/app/sdnhub_apps/run_sdnhub_apps.sh
