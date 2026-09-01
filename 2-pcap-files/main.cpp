#include <memory>
#include <iostream>
#include "stdlib.h"
#include "PcapFileDevice.h"

// Tutorial #2: Read/Write Pcap Files

int main(int argc, char* argv[])
{
	// PcapPlusPlus supports two packet-capture file formats (pcap and pcap-ng).
	// If we know the format, we can use format-specific Reader or Writer
	// 		e.g., PcapFileReaderDevice or PcapNgFileReaderDevice.
	// We can also use IFileReaderDevice, which works for both file formats.
	
	// std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader("input.pcap"));
	auto reader = pcpp::IFileReaderDevice::tryCreateReader("input.pcap");

	// verify that a reader interface was created.
	if (reader == nullptr)
	{
		std::cerr << "Cannot determine the reader for file type." << std::endl;
		return 1;
	}

	// open reader
	if (!reader->open()) {
		std::cerr << "Cannot open input.pcap for reading." << std::endl;
		return 1;
	}

	// create a pcap file writer.
	pcpp::PcapFileWriterDevice pcapWriter("output.pcap", pcpp::LINKTYPE_ETHERNET);

	// try to open the file for writing.
	if (!pcapWriter.open()) {
		std::cerr << "Cannot open output.pcap for writing." << std::endl;
		return 1;
	}

	// create a pcap-ng file writer.
	pcpp::PcapNgFileWriterDevice pcapNgWriter("output.pcapng");

	if (!pcapNgWriter.open()) {
		std::cerr << "Cannot open output.pcapng for writing." << std::endl;
		return 1;
	}

	// set a BPF filter for the reader - only packets that match the filter will be read
	if (!reader->setFilter("net 98.138.19.88")) {
		std::cerr << "Cannot set filter for file reader" << std::endl;
		return 1;
	}

	// packet container
	pcpp::RawPacket rawPacket;

	// a while loop that will continue as long as there are packets 
	// in the input file matching the filter.
	while (reader->getNextPacket(rawPacket)) {
		// write each packet to both writers
		pcapWriter.writePacket(rawPacket);
		pcapNgWriter.writePacket(rawPacket);
	}

	// use lambda to simplify statistics output
	auto printStats = [](const std::string& writerName, const pcpp::PcapStats& stats) {
		std::cout << "Written " << stats.packetsRecv << " packets successfully to " 
					<< writerName << " and " << stats.packetsDrop 
					<< " packets could not be written" << std::endl;
	};

	// create stats object
	pcpp::PcapStats stats;

	// read stats from reader and print them
	reader->getStatistics(stats);
	
	std::cout << "Read " << stats.packetsRecv << " packets successfully and " 
				<< stats.packetsDrop << " packets could not be read" << std::endl;
	
	// read stats from pcap writer and print them
	pcapWriter.getStatistics(stats);
	printStats("pcap writer", stats);

	// read stats from pcap-ng writer and print them
	pcapNgWriter.getStatistics(stats);
	printStats("pcap-ng writer", stats);

	// close reader and writer
	reader->close();
	pcapWriter.close();
	pcapNgWriter.close();

	return 0;
}