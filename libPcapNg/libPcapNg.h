#pragma once
#include <vector>
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


int main();
