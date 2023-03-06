/*
	(C) 2023 paging, All rights reserved.

	GNU General Public License v3.0
*/

#include "Server.h"

void HandlePacket( STCP::Packet& packet, STCP::Server* server, SOCKET client_socket )
{
	std::printf( "Received packet with ID: %d\n", packet.m_Header.m_ID );

	std::printf( "Data: %s\n", packet.m_Data );

	STCP::Packet response( STCP::Packet::ID::RESPONSE );
	response.m_Data[0] = 0x21;
	response.m_Data[1] = 0x1D;

	response.m_Header.m_Size = 2;

	if ( !server->Send( client_socket, response ) )
		std::cout << "Failed to send packet" << std::endl;
}

int main( )
{
	using namespace STCP;

	Config server_config;
	server_config.IP = "127.0.0.1";
	server_config.Port = 1337;

	try {
		Server Server( server_config, HandlePacket );

	}
	catch ( std::exception& e )
	{
		std::cout << e.what( ) << std::endl;
	}

	return 0;
}