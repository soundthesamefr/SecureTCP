#include "SecureTCP.h"

STCP::Server::Server( STCP::Config config ) : m_Config(config)
{
	if ( sodium_init( ) == -1 )
	{
		throw std::exception("Failed to initialize sodium.");
	}

	if ( crypto_box_keypair( m_KeyPair.public_key, m_KeyPair.secret_key ) == -1 )
	{
		throw std::exception("Failed to generate key pair.");
	}

	if ( WSAStartup( MAKEWORD( 2, 2 ), &m_WSAData ) != 0 )
	{
		throw std::exception( "Failed to initialize Winsock." );
	}

	m_ListenSocket = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

	if ( m_ListenSocket == INVALID_SOCKET )
	{
		throw std::exception( "Failed to create socket." );
		return;
	}

	sockaddr_in SockAddr;
	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = htons( m_Config.Port );
	SockAddr.sin_addr.s_addr = inet_addr( m_Config.IP );
	
	if ( bind( m_ListenSocket, (SOCKADDR*)(&SockAddr), sizeof( SockAddr ) ) == SOCKET_ERROR )
	{
		throw std::exception( "Failed to bind socket." );
		return;
	}

	if ( listen( m_ListenSocket, SOMAXCONN ) == SOCKET_ERROR )
	{
		throw std::exception( "Failed to listen on socket." );
		return;
	}

	while ( true )
	{
		SOCKET Client = accept( m_ListenSocket, NULL, NULL );
		if ( Client != INVALID_SOCKET )
		{
			std::printf("Client connected.\n");
			std::thread( HandleClient, std::move( Client ), this ).detach( );
		}
	}
}

bool STCP::Server::Send( SOCKET ClientSocket, Packet packet )
{
	auto KPIterator = m_KeyMap.find( ClientSocket );
	if ( KPIterator != m_KeyMap.end( ) )
	{
		key_pair ClientKP = KPIterator->second;

		unsigned char* EncryptedData = new unsigned char[sizeof( Packet ) + crypto_box_MACBYTES];
		unsigned char* Nonce = new unsigned char[crypto_box_NONCEBYTES];

		randombytes_buf( Nonce, crypto_box_NONCEBYTES );

		printf("Nonce: ");
		for ( int i = 0; i < crypto_box_NONCEBYTES; i++ )
		{
			printf("%02X ", Nonce[i]);
		}
		printf("\n");

		if ( crypto_box_easy( EncryptedData, packet.m_Data, sizeof( Packet ), Nonce, ClientKP.public_key, m_KeyPair.secret_key ) == -1 )
		{
			throw std::exception("Failed to encrypt packet.");
		}

		if ( send( ClientSocket, (char*)Nonce, crypto_box_NONCEBYTES, 0 ) == SOCKET_ERROR )
		{
			std::printf( "Failed to send nonce: %d\n", WSAGetLastError() );
			return false;
		}

		if ( send( ClientSocket, (char*)EncryptedData, sizeof( Packet ) + crypto_box_MACBYTES, 0 ) == SOCKET_ERROR )
		{
			std::printf( "Failed to send encrypted data: %d\n", WSAGetLastError() );
			return false;
		}

		delete[] EncryptedData;
		delete[] Nonce;
	}
}

bool STCP::Server::Recv( SOCKET ClientSocket, Packet* packet )
{
	auto KPIterator = m_KeyMap.find( ClientSocket );
	if ( KPIterator != m_KeyMap.end( ) )
	{
		key_pair ClientKP = KPIterator->second;

		unsigned char* Nonce = new unsigned char[crypto_box_NONCEBYTES];
		unsigned char* EncryptedData = new unsigned char[packet->m_Header.m_Size + crypto_box_MACBYTES];

		if ( recv( ClientSocket, (char*)Nonce, crypto_box_NONCEBYTES, 0 ) == SOCKET_ERROR )
		{
			std::printf( "Failed to recv nonce: %d\n", WSAGetLastError() );
			return false;
		}

		if ( recv( ClientSocket, (char*)EncryptedData, packet->m_Header.m_Size + crypto_box_MACBYTES, 0 ) == SOCKET_ERROR )
		{
			std::printf( "Failed to recv encrypted data: %d\n", WSAGetLastError() );
			return false;
		}

		if ( crypto_box_open_easy( packet->m_Data, EncryptedData, packet->m_Header.m_Size + crypto_box_MACBYTES, Nonce, ClientKP.public_key, m_KeyPair.secret_key ) == -1 )
		{
			throw std::exception("Failed to decrypt packet.");
		}

		delete[] Nonce;
		delete[] EncryptedData;
	}
}

bool STCP::Client::Send( Packet packet )
{
	unsigned char* EncryptedData = new unsigned char[packet.m_Header.m_Size + crypto_box_MACBYTES];
	unsigned char* Nonce = new unsigned char[crypto_box_NONCEBYTES];

	randombytes_buf( Nonce, crypto_box_NONCEBYTES );

	if ( crypto_box_easy( EncryptedData, packet.m_Data, packet.m_Header.m_Size, Nonce, m_ServerKP.public_key, m_KeyPair.secret_key ) == -1 )
	{
		throw std::exception("Failed to encrypt packet.");
	}

	if ( send( m_ConnectSocket, (char*)Nonce, crypto_box_NONCEBYTES, 0 ) == SOCKET_ERROR )
	{
		std::printf( "Failed to send nonce: %d\n", WSAGetLastError() );
		return false;
	}

	if ( send( m_ConnectSocket, (char*)EncryptedData, packet.m_Header.m_Size + crypto_box_MACBYTES, 0 ) == SOCKET_ERROR )
	{
		std::printf( "Failed to send encrypted data: %d\n", WSAGetLastError() );
		return false;
	}

	delete[] EncryptedData;
	delete[] Nonce;
}

bool STCP::Client::Recv( Packet* packet )
{
	unsigned char* Nonce = new unsigned char[crypto_box_NONCEBYTES];
	unsigned char* EncryptedData = new unsigned char[sizeof( Packet ) + crypto_box_MACBYTES];

	if ( recv( m_ConnectSocket, (char*)Nonce, crypto_box_NONCEBYTES, 0 ) == SOCKET_ERROR )
	{
		std::printf( "Failed to recv nonce: %d\n", WSAGetLastError() );
		return false;
	}

	if ( recv( m_ConnectSocket, (char*)EncryptedData, sizeof( Packet ) + crypto_box_MACBYTES, 0 ) == SOCKET_ERROR )
	{
		std::printf( "Failed to recv encrypted data: %d\n", WSAGetLastError() );
		return false;
	}

	if ( crypto_box_open_easy( packet->m_Data, EncryptedData, sizeof( Packet ) + crypto_box_MACBYTES, Nonce, m_ServerKP.public_key, m_KeyPair.secret_key ) == -1 )
	{
		throw std::exception("Failed to decrypt packet.");
	}

	delete[] Nonce;
	delete[] EncryptedData;
}

void STCP::Server::HandleClient( SOCKET ClientSocket, Server* Srv )
{
	Packet ConfirmPacket( Packet::INIT );
	key_pair ClientKP = { 0 };

	if ( send( ClientSocket, (char*)&Srv->m_KeyPair.public_key, sizeof( Srv->m_KeyPair.public_key ), 0 ) == SOCKET_ERROR )
	{
		std::printf( "send failed: %d\n", WSAGetLastError( ) );
		goto exit;
	}

	if ( recv( ClientSocket, (char*)&ClientKP.public_key, sizeof( ClientKP.public_key ), 0 ) == SOCKET_ERROR )
	{
		std::printf( "recv failed: %d\n", WSAGetLastError() );
		goto exit;
	}

	Srv->m_KeyMap[ClientSocket] = ClientKP;

	*reinterpret_cast<uint8_t*>(ConfirmPacket.m_Data) = INIT_KEY;
	ConfirmPacket.m_Header.m_Size = 1;

	if ( !Srv->Send( ClientSocket, ConfirmPacket ) )
	{
		std::printf("Failed to send confirmation packet.\n");
		goto exit;
	}

	while ( true )
	{
	}

exit:
	closesocket(ClientSocket);
}

STCP::Client::Client( Config config ) : m_Config(config)
{
	if ( sodium_init( ) == -1 )
	{
		throw std::exception("Failed to initialize sodium.");
	}

	if ( WSAStartup( MAKEWORD( 2, 2 ), &m_WSAData ) != 0 )
	{
		throw std::exception("Failed to initialize Winsock.");
	}

	m_ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct addrinfo* result = NULL, * ptr = NULL, hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if ( getaddrinfo( m_Config.IP, std::to_string( m_Config.Port ).c_str( ), &hints, &result ) != 0 )
	{
		throw std::exception("Failed to get address info.");
	}

	for ( ptr = result; ptr != nullptr; ptr = ptr->ai_next )
	{
		m_ConnectSocket = socket( ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol );
		if ( connect( m_ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen ) )
		{
			throw std::exception("Failed to connect to server.");
		}
		break;
	}

	if ( crypto_box_keypair( m_KeyPair.public_key, m_KeyPair.secret_key ) == -1 )
	{
		throw std::exception("Failed to generate key pair.");
	}

	int iResult = recv( m_ConnectSocket, (char*)&m_ServerKP.public_key, sizeof( m_ServerKP.public_key ), 0 );

	if ( iResult == SOCKET_ERROR )
	{
		throw std::exception("Failed to receive server key.");
	}

	if ( iResult != crypto_box_PUBLICKEYBYTES )
	{
		throw std::exception("Received invalid server key.");
	}

	if ( send( m_ConnectSocket, (char*)&m_KeyPair.public_key, sizeof( m_KeyPair.public_key ), 0 ) == SOCKET_ERROR )
	{
		throw std::exception( "Failed to send client key. ");
	}

	Packet InitPacket;
	if ( !Recv( &InitPacket ) )
	{
		throw std::exception( "Failed to receive confirmation packet." );
	}

	if ( InitPacket.m_Header.m_ID != Packet::INIT 
		 || *reinterpret_cast<uint8_t*>(InitPacket.m_Data) != INIT_KEY )
	{
		throw std::exception( "Received invalid confirmation packet. ");
	}
}