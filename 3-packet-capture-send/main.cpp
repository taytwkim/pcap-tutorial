#include <chrono>
#include <iostream>
#include <algorithm>
#include <thread>
#include "Packet.h"	// added
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"

/*
 * Part 3: Capturing and Sending Packets
 * 
 * 1. Find and open a device (network interface on your machine).
 * 2. Create an instance of the stats struct.
 * 3. Demonstration of three types of packet capturing.
 * 		- Asynchronous packet capture using a callback function.
 *		- Asynchronous packet capture using a packet list (vector).
 *		- Asynchronous (blocking) packet capture using a callback function.
 */

// Container to record packet stats. 
struct PacketStats {
	int ethPacketCount = 0;
	int ipv4PacketCount = 0;
	int ipv6PacketCount = 0;
	int tcpPacketCount = 0;
	int udpPacketCount = 0;
	int dnsPacketCount = 0;
	int httpPacketCount = 0;
	int sslPacketCount = 0;

	// constructor is optional since the members are already initialized.
	PacketStats() = default;

	// clear all stats
	void clear() {
		ethPacketCount = 0;
		ipv4PacketCount = 0;
		ipv6PacketCount = 0;
		tcpPacketCount = 0;
		udpPacketCount = 0;
		dnsPacketCount = 0;
		httpPacketCount = 0;
		sslPacketCount = 0;
	}

	void consumePacket(pcpp::Packet& packet) {
		if (packet.isPacketOfType(pcpp::Ethernet)) {
			++ethPacketCount;
		}
		
		if (packet.isPacketOfType(pcpp::IPv4)) {
			++ipv4PacketCount;
		}
		
		if (packet.isPacketOfType(pcpp::IPv6)) {
			++ipv6PacketCount;
		}
		
		if (packet.isPacketOfType(pcpp::TCP)) {
			++tcpPacketCount;
		}
		
		if (packet.isPacketOfType(pcpp::UDP)) {
			++udpPacketCount;
		}
		
		if (packet.isPacketOfType(pcpp::DNS)) {
			++dnsPacketCount;
		}

		if (packet.isPacketOfType(pcpp::HTTP)) {
			++httpPacketCount;
		}

		if (packet.isPacketOfType(pcpp::SSL)) {
			++sslPacketCount;
		}
	}

	void printToConsole() {
		std::cout << "Ethernet packet count:	" << ethPacketCount << "\n"
				  << "IPv4 packet count:		" << ipv4PacketCount << "\n"
				  << "IPv6 packet count: 		" << ipv6PacketCount << "\n"
				  << "TCP packet count: 		" << tcpPacketCount << "\n"
				  << "UDP packet count: 		" << udpPacketCount << "\n"
				  << "DNS packet count: 		" << dnsPacketCount << "\n"
				  << "HTTP packet count: 		" << httpPacketCount << "\n"
				  << "SSL packet count: 		" << sslPacketCount << std::endl; 
	}
};

// Callback for async capture called each time a packet is captured.
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
	// Extract stats struct from cookie
	// Cookie is a generic user-data pointer to represent stats
	// PacketStats is custom struct in this file, PcapPlusPlus provides a
	// generic function signature to support custom types. 
	auto* stats = static_cast<PacketStats*>(cookie);

	// parse the raw packet
	pcpp::Packet parsedPacket(packet);

	// collect stats from packet
	stats->consumePacket(parsedPacket);
}

int main (int argc, char* argv[]) {
	// IPv4 address of the interface that we want to sniff.

	std::string interfaceIPAddr = "10.0.0.1";

	// Find interface by IP address.
	// A "device" here just means a network interface on your machine, such as WiFi or Ethernet.
	// Different network interfaces on the same machine can have different IP addresses.
	
	// auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
	auto* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(interfaceIPAddr);

	if (dev == nullptr) {
		std::cerr << "Cannot find interface IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
		return 1;
	}

	// print device info
	std::cout << "Interface info: " << "\n"
			  << "	Interface name:			" << dev->getName() << "\n"
			  << "	Interface description:	" << dev->getDesc() << "\n"
			  << "	MAC address:			" << dev->getMacAddress() << "\n"
			  << "	Default gateway: 		" << dev->getDefaultGateway() << "\n"
			  << "	Interface MTU:			" << dev->getMtu() << std::endl;
	
	if (!dev->getDnsServers().empty()) {
		std::cout << "	DNS server:			" << dev->getDnsServers().front() << std::endl;
	}

	// open the device before start capturing/sending packets
	if (!dev->open()) {
		std::cerr << "Cannot open device" << std::endl;
		return 1;
	}

	PacketStats stats;
	
	// Async packet capture using a callback function
	// packet is captured by a different thread spawned by PcapPlusPlus, not the main thread.
	// the async thread calls the callback function.
	std::cout << "Start async capture..." << std::endl;

	dev->startCapture(onPacketArrives, &stats);

	// sleep for 10 seconds in the main thread, packets are captured in the async thread.
	
	// pcpp::multiPlatformSleep(10);
	std::this_thread::sleep_for(std::chrono::seconds(10));
	
	// stop capturing packets
	dev->stopCapture();

	// print the results
	std::cout << "Results:" << std::endl;
	stats.printToConsole();

	return 0;
}
