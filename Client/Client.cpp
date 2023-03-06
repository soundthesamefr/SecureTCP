#include "Client.h"

int main( )
{
	using namespace STCP;

	Config ClientConfig;
	ClientConfig.IP = "127.0.0.1";
	ClientConfig.Port = 1337;

	try {
		Client Client(ClientConfig);

		std::printf("Client started on %s:%d\n", ClientConfig.IP, ClientConfig.Port);
	}
	catch ( std::exception& e )
	{
		std::cout << e.what( ) << std::endl;
	}
}