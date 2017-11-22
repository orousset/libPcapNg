// libPcapNg.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include "libPcapNg.h"
#include <vector>
#include <string>
#include <sstream>

const bool DEBUG = true;
const int IPpayloadOffset = 0x0e; // Offset to the start of the IP packet from the start of the ethernet frame
const int FSFB2OffSetPayLoad = 0x49; // Offset to the start of the FSFB2 payload from the start of the ethernet frame
const int packetDataOffsetEnhPB = 28; // Offset of packet data position in enhanced Packet Block
const int TimeStampHighOffsetEnhPB = 12; // Offset of TimeStamp (High) position in enhanced Packet Block
const int TimeStampLowOffsetEnhPB = 16; // Offset of TimeStamp (Low) position in enhanced Packet Block
const int IPpacketWidth = 0x10 + packetDataOffsetEnhPB; // Offset to the IP packet size from the start of the ethernet frame
const int IPOffsetprotocol = 0x17 + packetDataOffsetEnhPB; // Offset to the IP protocol from the start of the ethernet frame
const int IPSrcOffset = 0x1A + packetDataOffsetEnhPB; // Offset to the Source IP address from the start of the ethernet frame
const int IPDstOffset = 0x1E + packetDataOffsetEnhPB; // Offset to the Destination IP address from the start of the ethernet frame
const int PortSrcOffset = 0x22 + packetDataOffsetEnhPB; // Offset to the Source Port from the start of the ethernet frame
const int PortDstOffset = 0x24 + packetDataOffsetEnhPB; // Offset to the Destination Port from the start of the ethernet frame
const int MAXBuffer = 1<<24; // Maximum size of file to load in memory is 2^24 bytes
const int BSDcode = 0x80; // Application code for BSD message
const std::string BLOCKTYPE_NG = { 0x0A, 0x0D, 0x0D, 0x0A }; // block type for pcapng file
const std::string BYTEORDERMAGIC_BE = { 0x1A, 0x2B, 0x3C, 0x4D }; // Byte Order Magic for Big Endian machine
const std::string BYTEORDERMAGIC_LE = { 0x4D, 0x3C, 0x2B, 0x1A }; // Byte Order Magic for Little Endian machine
const int UDP = 0x11; // Code of UDP packet

// Convert single char to (unsigned) int
int char2int(char input) {
	int output;
	(int)input < 0 ? output = input + 256 : output = input;
	return output;
}

// Convert a number of char into (unsigned) int. start is the first element in the char[], width and Endianness are required
int char2int(char *input, int start, int width, endianness iEndianess) {
	int output = 0;
	if (iEndianess == LITTLE_ENDIAN) {
		for (int cpt = 0; cpt < width; cpt++) {
			output += char2int(input[start + cpt]) * (1 << cpt * 8);
		}
	}
	if (iEndianess == BIG_ENDIAN) {
		for (int cpt = 0; cpt < width; cpt++) {
			output += char2int(input[start + cpt]) * (1 << (width - 1 - cpt) * 8);
		}
	}
	return output;
}

class fileManagement {
private:
	char* memblock; // Temporary buffer for reading pCapNG file
	int nbByteinBuffer = 0;
	endianness localEndianness; // Temporary variable for storing the endianness of the machine capture the pCap
	int globalHeaderSize = 0;
	int currentPos = 0; // Temporary counter to track position within the pCap
	std::string namePcapFile; // Name of the pCapNG file
	FSFB2BSDpacket* lastBSDptr = NULL; // Keep track of the last BSD (for quick addition to linked list)

public:
//	std::vector<FSFB2BSDpacket> pCapFSFB2;
	FSFB2BSDpacket* rootBSDptr;

	fileManagement(std::string name_input) {
		namePcapFile = name_input;
		memblock = NULL;
		rootBSDptr = NULL;
		lastBSDptr = rootBSDptr;
	}

	~fileManagement() {
		FSFB2BSDpacket myBSD = *rootBSDptr;
		
		if (memblock != NULL) { delete[] memblock; }
		while (myBSD.nextFSFB2BSDPacket != NULL) {
			if (myBSD.payload != NULL) { delete myBSD.payload; }
			myBSD = *myBSD.nextFSFB2BSDPacket;
		}
	}

	// Load the pCapNG file in memory
	bool Load() {
		std::ifstream file(namePcapFile, std::ios::in | std::ios::binary | std::ios::ate);
		if (file.is_open()) {
			std::streampos size = file.tellg(); // size of the file
			nbByteinBuffer = size;
			memblock = new char[size];
			file.seekg(0, std::ios::beg);
			file.read(memblock, size);
			file.close();
			return(true);
		}
		return(false);
	}

	// Parse the Section Header
	bool parseSectionHeader() {
		std::string BT;
		
		BT.append(1, memblock[0]).append(1, memblock[1]).append(1, memblock[2]).append(1, memblock[3]); // concatenate bytes 0 to 3 to build Block Type
		if (BT != BLOCKTYPE_NG) { std::cout << "Incorrect file format: header does not correspond to pCapNG file" << std::endl; return(false); }
		else {
			globalHeaderSize = char2int(memblock, 4, 4, LITTLE_ENDIAN);
			std::string BOM;
			BOM.append(1, memblock[8]).append(1, memblock[9]).append(1, memblock[10]).append(1, memblock[11]); // concatenate bytes 8 to 11 to build Byte-Order Magic (endianness test) 
			if (BOM == BYTEORDERMAGIC_BE) { localEndianness = BIG_ENDIAN; }
			else if (BOM == BYTEORDERMAGIC_LE) { localEndianness = LITTLE_ENDIAN; }
			else { std::cout << "Incorrect file format: endianness test incorrect" << std::endl; return(false); }

		}
		currentPos += globalHeaderSize;
		return(true);
	}

	// Parse the Interface Description
	bool parseInterfaceDescription() {
		int interfaceBlockLength = 0;
		
		interfaceBlockLength = char2int(memblock, currentPos + 4, 4, localEndianness);
		currentPos += interfaceBlockLength;
		return true;
	}

	bool parseEnhancedPacketBlock(std::string IPsrc, std::string IPdst, int portSrc, int portDst) {
		int interfaceBlockLength = 0;

		interfaceBlockLength = char2int(memblock, currentPos + 4, 4, localEndianness);
		if (char2int(memblock[currentPos + IPOffsetprotocol]) != UDP) {
			currentPos += interfaceBlockLength;
			return(true); // if the packet is not UDP go to next
		}
//		pCapFSFB2.push_back(*new(FSFB2BSDpacket));

		pCapFSFB2.back().IPsrc = std::to_string(char2int(memblock[currentPos + IPSrcOffset]))
			+ "." + std::to_string(char2int(memblock[currentPos + IPSrcOffset + 1]))
			+ "." + std::to_string(char2int(memblock[currentPos + IPSrcOffset + 2])) 
			+ "." + std::to_string(char2int(memblock[currentPos + IPSrcOffset + 3]));
		if (pCapFSFB2.back().IPsrc != IPsrc) { currentPos += interfaceBlockLength; return true; }
		pCapFSFB2.back().IPdst = std::to_string(char2int(memblock[currentPos + IPDstOffset])) 
			+ "." + std::to_string(char2int(memblock[currentPos + IPDstOffset + 1]))
			+ "." + std::to_string(char2int(memblock[currentPos + IPDstOffset + 2])) 
			+ "." + std::to_string(char2int(memblock[currentPos + IPDstOffset + 3]));
		if (pCapFSFB2.back().IPdst != IPdst) { currentPos += interfaceBlockLength; return true; }
		// Note: Network convention is big endian - not related to the capture endianness of the machine
		pCapFSFB2.back().portsrc = char2int(memblock, currentPos + PortSrcOffset, 2, BIG_ENDIAN); 
		pCapFSFB2.back().portdst = char2int(memblock, currentPos + PortDstOffset, 2, BIG_ENDIAN);
		pCapFSFB2.back().timestampH = char2int(memblock, currentPos + TimeStampHighOffsetEnhPB, 4, BIG_ENDIAN);
		pCapFSFB2.back().timestampL = char2int(memblock, currentPos + TimeStampLowOffsetEnhPB, 4, BIG_ENDIAN);
		int payloadWidth = char2int(memblock, currentPos + IPpacketWidth, 2, BIG_ENDIAN); // size of the IP payload
		pCapFSFB2.back().payload = new char[payloadWidth];
		memcpy(pCapFSFB2.back().payload, memblock + currentPos + IPpayloadOffset + packetDataOffsetEnhPB, payloadWidth);
		if (DEBUG) {
			std::cout << "IP Source: " << pCapFSFB2.back().IPsrc << ":" << pCapFSFB2.back().portsrc << " and IP Destination: " << pCapFSFB2.back().IPdst << ":" << pCapFSFB2.back().portdst << std::endl;
			for (int cpt = 0; cpt < payloadWidth; cpt++) {
				std::cout << (int)pCapFSFB2.back().payload[cpt] << " ";
			}
			std::cout << std::endl;
		}
		currentPos += interfaceBlockLength;
		return true;
	}

	bool parseFSFB2(std::string ipSrc, std::string ipDst, int portSrc, int portDst) {
		bool EOFreached = false;

		if (parseSectionHeader() == false) { return false; }
		while (!EOFreached) {
			int blockType = char2int(memblock, currentPos, 4, LITTLE_ENDIAN);

			if (blockType == 1) {
				if (parseInterfaceDescription() == false) { return false; }
			}
			if (blockType == 6) {
				if (parseEnhancedPacketBlock(ipSrc, ipDst, portSrc, portDst) == false) { return false; }
			}
			if (currentPos >= nbByteinBuffer) { EOFreached = true; }
		}
		std::cout << "End of memory buffer reached" << std::endl;
		return true;
	}
};

int main()
{
	std::string name_file;
	std::cout << "Please provide name of the pcapng file: ";
	getline(std::cin, name_file);
	fileManagement* myFile = new fileManagement(name_file);
	if (myFile->Load() == true) {
		std::cout << "Successful loading in memory" << std::endl;
	}
	else { std::cout << "Error when attempting to open the file " << name_file << std::endl; return -1; }
	if (myFile->parseFSFB2("10.0.4.7", "10.0.5.4", 20000, 20000) == false) { return -2; }
	
	int tp; std::cin >> tp;
	delete myFile;
	std::cin >> tp;
	return 0;
}

