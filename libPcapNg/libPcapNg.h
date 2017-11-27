#pragma once

#include <string>

enum endianness { BIG_ENDIAN, LITTLE_ENDIAN};

class FSFB2BSDpacket {
public:
	std::string IPsrc;
	std::string IPdst;
	int portsrc, portdst;
	int timestampH, timestampL;
	char* payload;
	FSFB2BSDpacket *nextFSFB2BSDPacket;

	FSFB2BSDpacket();
	~FSFB2BSDpacket();
};

class FileManagement {
private:
	char* memblock; // Temporary buffer for reading pCapNG file
	int nbByteinBuffer;
	endianness localEndianness; // Temporary variable for storing the endianness of the machine capture the pCap
	int globalHeaderSize; // Size of the global header
	int currentPos; // Temporary counter to track position within the pCap
	std::string namePcapFile; // Name of the pCapNG file
	FSFB2BSDpacket* lastBSDptr; // Keep track of the last BSD (for quick addition to linked list)
	int nbFilteredPacket; // Keep track of the total number of packet found according to provided filter

public:
	FSFB2BSDpacket* rootBSDptr;
	FileManagement(std::string name_input);
	~FileManagement();

	bool Load();
	bool parseSectionHeader();
	bool addFSFB2BSDPacket();
	bool addFSFB2BSDPacket(std::string IPsrc, std::string IPdst, int portSrc, int portDst);
	bool parseInterfaceDescription();
	bool parseEnhancedPacketBlock(std::string IPsrc, std::string IPdst, int portSrc, int portDst);
	bool parseFSFB2(std::string ipSrc, std::string ipDst, int portSrc, int portDst);
};

int main();
