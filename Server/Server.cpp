#include "Server.h"

int main( )
{
	using namespace STCP;

	Config ServerConfig;
	ServerConfig.IP = "127.0.0.1";
	ServerConfig.Port = 1337;

	try {
		Server Server(ServerConfig);

		std::printf("Server started on %s:%d\n", ServerConfig.IP, ServerConfig.Port);

	}
	catch ( std::exception& e )
	{
		std::cout << e.what( ) << std::endl;
	}

}