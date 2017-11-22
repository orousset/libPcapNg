#pragma once
#include <vector>

enum endianness { BIG_ENDIAN, LITTLE_ENDIAN};

struct FSFB2BSDpacket {
	std::string IPsrc;
	std::string IPdst;
	int portsrc, portdst;
	int timestampH, timestampL;
	char* payload;
	FSFB2BSDpacket *nextFSFB2BSDPacket;
};


int main();
