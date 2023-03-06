
# SecureTCP

Base TCP server framework for Windows that incorperates public-key encryption. 


## Network Analysis

SecureTCP uses Authenticated Encryption with Additional Data (AEAD) scheme, specifically Poly1305 and XSalsa20 algorithms, for encryption.
 
AEAD ensures confidentiality, integrity, and authenticity of the encrypted data, and the Poly1305 and XSalsa20 algorithms provide strong and efficient cryptographic security.

![App Screenshot](https://i.ibb.co/KDKPvt8/Secure-TCP-Media.png)


## License

[GNU General Public License v3.0](https://github.com/soundthesamefr/SecureTCP/blob/master/license/)


## Usage/Examples

Initialize Server class
```cpp
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
```
Handle Packets through callback
```cpp
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
```

Client Example
```cpp
int main( )
{
	using namespace STCP;

	Config ClientConfig;
	ClientConfig.IP = "127.0.0.1";
	ClientConfig.Port = 1337;

	try {
		Client Client(ClientConfig);

		Packet packet(Packet::ID::REQUEST);

		char buffer[] = "Hello World!";
		memcpy(packet.m_Data, buffer, sizeof(buffer));

		packet.m_Header.m_Size = sizeof(buffer);

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

	return 0;
}
```
