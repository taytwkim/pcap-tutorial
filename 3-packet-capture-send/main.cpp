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
 * 1. Find and open a "device" (network interface on your machine).
 * 2. Create an instance of the stats struct.
 * 3. Demonstrate three types of packet capturing.
 * 		- Async packet capture using a callback function.
 *		- Async packet capture using a packet list (vector).
 *		- Async (blocking) packet capture using a callback function.
 * 4. Demonstrate sending packets.
 * 		- Send one packet at a time.
 * 		- Send batch of packets.
 * 5. Filtering packets.
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

	// Constructor is optional since the members are already initialized.
	PacketStats() = default;

	// Clear all stats.
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

// Async callback called each time a packet is captured.
static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
	// Extract stats struct from "cookie".
	// Cookie is a generic user-data pointer to represent stats.
	// PacketStats is custom struct defined in this file, PcapPlusPlus provides a
	// generic function signature that support custom types. 
	auto* stats = static_cast<PacketStats*>(cookie);

	// Parse the raw packet.
	pcpp::Packet parsedPacket(packet);

	// Collect stats from packet.
	stats->consumePacket(parsedPacket);
}

// Blocking callback called each time a packet is captured.
static bool onPacketArrivesBlockingMode(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie) {
	auto* stats = static_cast<PacketStats*>(cookie);
	pcpp::Packet parsedPacket(packet);
	stats->consumePacket(parsedPacket);

	// false here means we don't want to stop capturing after this callback.
	return false;
}

int main (int argc, char* argv[]) {
	// IPv4 address of the interface we want to sniff.
	std::string interfaceIPAddr = "172.20.172.55";

	// Find interface by IP address.
	// A "device" here just means a network interface on your machine, e.g., WiFi or Ethernet.
	// Different network interfaces on the same machine can have different IP addresses.
	
	// auto* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);	// deprecated
	auto* dev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByIp(interfaceIPAddr);

	if (dev == nullptr) {
		std::cerr << "Cannot find interface IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
		return 1;
	}

	// Print device info.
	std::cout << "Interface info: " << "\n"
			  << "	Interface name:			" << dev->getName() << "\n"
			  << "	Interface description:	" << dev->getDesc() << "\n"
			  << "	MAC address:			" << dev->getMacAddress() << "\n"
			  << "	Default gateway: 		" << dev->getDefaultGateway() << "\n"
			  << "	Interface MTU:			" << dev->getMtu() << std::endl;
	
	if (!dev->getDnsServers().empty()) {
		std::cout << "	DNS server:			" << dev->getDnsServers().front() << std::endl;
	}

	// Open device before start capturing/sending packets.
	if (!dev->open()) {
		std::cerr << "Cannot open device" << std::endl;
		return 1;
	}

	PacketStats stats;
	
	// 1. Async packet capture using a callback function.
	
	// Packet is captured by a different thread spawned by PcapPlusPlus, not the main thread.
	// The async thread calls the callback function.
	std::cout << "\nStart async capture with callback function..." << std::endl;

	dev->startCapture(onPacketArrives, &stats);

	// Sleep for 10 seconds in the main thread, packets are captured in the async thread.
	
	// pcpp::multiPlatformSleep(10);	// deprecated
	std::this_thread::sleep_for(std::chrono::seconds(10));
	
	// Stop capturing packets.
	dev->stopCapture();

	// Print results.
	std::cout << "\nResults:" << std::endl;
	stats.printToConsole();

	stats.clear();

	// 2. Aync packet capture using a packet list (vector).

	// Supply PcapPlusPlus an instance of raw packet pointer list, and the async thread
	// will fill it with pointers to captured packets.
	// The advantage is that you can use the packets captured in the main thread.
	std::cout << "\nStart async capture with packet vector..." << std::endl;

	// Create an empty packet vector object.
	pcpp::RawPacketVector packetVec;

	// Start capturing packets. Packets will be added to the packet vector.
	dev->startCapture(packetVec);

	std::this_thread::sleep_for(std::chrono::seconds(10));

	// Stop capturing packets
	dev->stopCapture();

	// Go over packet vector and feed all packets to the stats object.
	for (const auto& packet : packetVec) {
		pcpp::Packet parsedPacket(packet);
		stats.consumePacket(parsedPacket);
	}

	std::cout << "\nResults: " << std::endl;
	stats.printToConsole();
	stats.clear();

	// 3. Synchronous (blocking) packet capture using a callback function.
	std::cout << "\nStart capture in blocking mode..." << std::endl;

	// Packet capturing stops when the callback returns true, but
	// our callback always returns false.
	// We can specify a timeout to stop capturing.
	dev->startCaptureBlockingMode(onPacketArrivesBlockingMode, &stats, 10);
	
	// No need to call stopCapture()!

	std::cout << "\nResults:" << std::endl;
	stats.printToConsole();

	// Send one raw packet at a time.
	std::cout << "\nSending " << packetVec.size() << " packets one by one..." << std::endl;

	// Go over the vector and send every packet that fits the interface MTU.
	const auto packetsSentIndividually = std::count_if(
		packetVec.begin(), packetVec.end(), [dev](pcpp::RawPacket* packet) {
			return dev->sendPacket(*packet, true);
		});

	const auto packetsNotSent = packetVec.size() - packetsSentIndividually;
	std::cout << packetsSentIndividually << " packets sent; "
			  << packetsNotSent << " packets not sent." << std::endl;

	// Send batch of packets.
	std::cout << "\nSending " << packetVec.size() << " packets..." << std::endl;
	
	int packetsSent = dev->sendPackets(packetVec, true);

	std::cout << packetsSent << " packets sent; "
			  << packetVec.size() - packetsSent << " packets not sent." << std::endl;

	// Filtering packets

	// Create a filter instance to capture only traffic from port 80.
	pcpp::PortFilter portFilter(80, pcpp::SRC_OR_DST);

	// Create a filter instance to capture only TCP traffic.
	pcpp::ProtoFilter protocolFilter(pcpp::TCP);

	// Create an AND filter that combines both filters - only TCP traffic on 80.
	pcpp::AndFilter andFilter;
	andFilter.addFilter(&portFilter);
	andFilter.addFilter(&protocolFilter);

	// Set filter on device.
	dev->setFilter(andFilter);

	std::cout << "\nStarting packet capture with a filter..." << std::endl;

	dev->startCapture(onPacketArrives, &stats);
	std::this_thread::sleep_for(std::chrono::seconds(10));
	dev->stopCapture();

	std::cout << "\nResults:" << std::endl;
	stats.printToConsole();

	dev->close();

	return 0;
}
