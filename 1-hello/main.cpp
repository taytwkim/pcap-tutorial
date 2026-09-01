#include <iostream>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>

// Tutorial #1: Hello World

int main (int argc, char* argv []) {
	pcpp::PcapFileReaderDevice reader("1_packet.pcap");

	// open a pcap file
	if (!reader.open()) {
		std::cerr << "Error opening the pcap file" << std::endl;
		return 1;
	}

	// read the first and only packet in the file.
	pcpp::RawPacket rawPacket;

	if (!reader.getNextPacket(rawPacket)) {
		std::cerr << "Couldn't read the first packet in the file." << std::endl;
		return 1;
	}

	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);

	// verify the packet is IPv4
	if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
		pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
		pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

		std::cout << "Source IP is '" << srcIP << "';"
			  		<< "Dest IP is '" << destIP << "'" << std::endl;
	}

	reader.close();

	return 0;
}