#include "Server.h"

void HandlePacket( STCP::Packet& packet, STCP::Server* server, SOCKET client_socket )
{
	std::printf( "Received packet with ID: %d\n", packet.m_Header.m_ID );

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

	Config ServerConfig;
	ServerConfig.IP = "127.0.0.1";
	ServerConfig.Port = 1337;

	try {
		Server Server( ServerConfig, HandlePacket );

		std::printf("Server started on %s:%d\n", ServerConfig.IP, ServerConfig.Port);

	}
	catch ( std::exception& e )
	{
		std::cout << e.what( ) << std::endl;
	}
}