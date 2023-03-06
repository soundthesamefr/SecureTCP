#include "Client.h"

int main( )
{
	using namespace STCP;

	Config ClientConfig;
	ClientConfig.IP = "127.0.0.1";
	ClientConfig.Port = 1337;

	try {
		Client Client(ClientConfig);

		Packet packet(Packet::ID::REQUEST);
		packet.m_Data[0] = 0x32;
		packet.m_Data[1] = 0x12;
		packet.m_Header.m_Size = 2;

		if( !Client.Send(packet) )
			std::cout << "Failed to send packet" << std::endl;

		Packet response;
		if( !Client.Recv(&response) )
			std::cout << "Failed to recv packet" << std::endl;

		std::cout << "Response: " << std::hex << (int)response.m_Data[0] << " " << (int)response.m_Data[1] << std::endl;
	}
	catch ( std::exception& e )
	{
		std::cout << e.what( ) << std::endl;
	}
}