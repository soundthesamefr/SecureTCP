/*
	(C) 2023 paging, All rights reserved.

	GNU General Public License v3.0
*/

#include "Client.h"

int main( )
{
	using namespace STCP;

	Config ClientConfig;
	ClientConfig.IP = "127.0.0.1";
	ClientConfig.Port = 1337;

	try {
		Client Client(ClientConfig);

		Packet packet;

		char buffer[] = "Hello World!";
		memcpy(packet.m_Data, buffer, sizeof(buffer));

		packet.m_Header.Size = sizeof(buffer);

		if( !Client.Send(packet) )
			std::cout << "Failed to send packet" << std::endl;

		Packet response;
		if( !Client.Recv(&response) )
			std::cout << "Failed to recv packet" << std::endl;

		for (int i = 0; i < response.m_Header.Size; i++)
			std::cout << response.m_Data[i] << std::endl;
	}
	catch ( std::exception& e )
	{
		std::cout << e.what( ) << std::endl;
	}
	return 0;
}