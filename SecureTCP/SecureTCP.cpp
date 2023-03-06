/*
	(C) 2023 paging, All rights reserved.

	GNU General Public License v3.0
*/

#include "SecureTCP.h"

STCP::Server::Server( STCP::Config server_config, std::function<void( Packet&, Server*, SOCKET )> handler )
	: m_Config( server_config ), m_Handler( handler )
{
	if ( sodium_init( ) == -1 ) 
	{
		throw std::runtime_error( "Failed to initialize sodium." );
	}

	if ( crypto_box_keypair( m_KeyPair.public_key, m_KeyPair.secret_key ) == -1 ) 
	{
		throw std::runtime_error( "Failed to generate key pair." );
	}

	if ( WSAStartup( MAKEWORD( 2, 2 ), &m_WSAData ) != 0 )
	{
		throw std::runtime_error( "Failed to initialize Winsock." );
	}

	m_ListenSocket = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

	if ( m_ListenSocket == INVALID_SOCKET )
	{
		throw std::runtime_error( "Failed to create socket." );
	}

	sockaddr_in sock_addr;
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons( m_Config.Port );
	sock_addr.sin_addr.s_addr = inet_addr( m_Config.IP );

	if ( bind( m_ListenSocket, reinterpret_cast<SOCKADDR*>(&sock_addr), sizeof( sock_addr ) ) == SOCKET_ERROR )
	{
		throw std::runtime_error( "Failed to bind socket." );
	}

	if ( listen( m_ListenSocket, SOMAXCONN ) == SOCKET_ERROR ) 
	{
		throw std::runtime_error( "Failed to listen on socket." );
	}

	while ( !m_Done ) 
	{
		SOCKET client = accept( m_ListenSocket, NULL, NULL );
		if ( client != INVALID_SOCKET )
		{
			std::thread( STCP::Server::HandleClient, client, this ).detach( );
		}
	}
}

bool STCP::Server::Send( SOCKET client_socket, Packet packet )
{
	//
	// Find the key pair for the client socket
	//

	auto key_pair_iterator = m_KeyMap.find( client_socket );
	if ( key_pair_iterator == m_KeyMap.end( ) )
	{
		return false;
	}

	key_pair client_key_pair = key_pair_iterator->second;

	//
	// Create arrays for the encrypted data and nonce
	//

	unsigned char* encrypted_data = new unsigned char[sizeof( Packet ) + crypto_box_MACBYTES];
	unsigned char* nonce = new unsigned char[crypto_box_NONCEBYTES];

	//
	// Generate a random nonce and encrypt the packet
	//

	randombytes_buf( nonce, crypto_box_NONCEBYTES );

	if ( crypto_box_easy( encrypted_data, (unsigned char*)(&packet), sizeof( Packet ), nonce, client_key_pair.public_key, m_KeyPair.secret_key ) == -1 )
	{
		return false;
	}

	//
	// Send the nonce and encrypted data to the client
	//

	if ( send( client_socket, (char*)nonce, crypto_box_NONCEBYTES, 0 ) == SOCKET_ERROR )
	{
		return false;
	}

	if ( send( client_socket, (char*)encrypted_data, sizeof( Packet ) + crypto_box_MACBYTES, 0 ) == SOCKET_ERROR )
	{
		return false;
	}

	//
	// Clean up
	//

	delete[] encrypted_data;
	delete[] nonce;

	return true;
}

bool STCP::Server::Recv( SOCKET client_socket, Packet* packet )
{
	//
	// Find the key pair for the client socket
	//

	auto key_pair_iterator = m_KeyMap.find( client_socket );
	if ( key_pair_iterator == m_KeyMap.end( ) )
	{
		return false;
	}

	key_pair client_key_pair = key_pair_iterator->second;

	//
	// Create arrays for the encrypted data and nonce
	//

	unsigned char* encrypted_data = new unsigned char[sizeof( Packet ) + crypto_box_MACBYTES];
	unsigned char* nonce = new unsigned char[crypto_box_NONCEBYTES];

	//
	// Receive the nonce and encrypted data from the client
	//

	if ( recv( client_socket, (char*)nonce, crypto_box_NONCEBYTES, 0 ) == SOCKET_ERROR )
	{
		return false;
	}

	if ( recv( client_socket, (char*)encrypted_data, sizeof( Packet ) + crypto_box_MACBYTES, 0 ) == SOCKET_ERROR )
	{
		return false;
	}

	//
	// Decrypt the packet
	//

	if ( crypto_box_open_easy( (unsigned char*)packet, encrypted_data, sizeof( Packet ) + crypto_box_MACBYTES, nonce, client_key_pair.public_key, m_KeyPair.secret_key ) == -1 )
	{
		return false;
	}

	//
	// Clean up
	//

	delete[] encrypted_data;
	delete[] nonce;

	return true;
}

void STCP::Server::Stop( )
{
	m_Done = true;
}

bool STCP::Client::Send( Packet packet )
{
	//
	// Create arrays for the encrypted data and nonce
	//

	unsigned char* encrypted_data = new unsigned char[sizeof( Packet ) + crypto_box_MACBYTES];
	unsigned char* nonce = new unsigned char[crypto_box_NONCEBYTES];

	//
	// Generate a random nonce and encrypt the packet
	//

	randombytes_buf( nonce, crypto_box_NONCEBYTES );

	if ( crypto_box_easy( encrypted_data, (unsigned char*)(&packet), sizeof( Packet ), nonce, m_ServerKP.public_key, m_KeyPair.secret_key ) == -1 )
	{
		return false;
	}

	//
	// Send the nonce and encrypted data to the server
	//

	if ( send( m_ConnectSocket, (char*)nonce, crypto_box_NONCEBYTES, 0 ) == SOCKET_ERROR )
	{
		return false;
	}

	if ( send( m_ConnectSocket, (char*)encrypted_data, sizeof( Packet ) + crypto_box_MACBYTES, 0 ) == SOCKET_ERROR )
	{
		return false;
	}

	//
	// Clean up
	//

	delete[] encrypted_data;
	delete[] nonce;

	return true;
}

bool STCP::Client::Recv( Packet* packet )
{
	//
	// Create arrays for the encrypted data and nonce
	//

	unsigned char* encrypted_data = new unsigned char[sizeof( Packet ) + crypto_box_MACBYTES];
	unsigned char* nonce = new unsigned char[crypto_box_NONCEBYTES];

	//
	// Receive the nonce and encrypted data from the server
	//

	if ( recv( m_ConnectSocket, (char*)nonce, crypto_box_NONCEBYTES, 0 ) == SOCKET_ERROR )
	{
		return false;
	}

	if ( recv( m_ConnectSocket, (char*)encrypted_data, sizeof( Packet ) + crypto_box_MACBYTES, 0 ) == SOCKET_ERROR )
	{
		return false;
	}

	//
	// Decrypt the packet
	//

	if ( crypto_box_open_easy( (unsigned char*)packet, encrypted_data, sizeof( Packet ) + crypto_box_MACBYTES, nonce, m_ServerKP.public_key, m_KeyPair.secret_key ) == -1 )
	{
		return false;
	}

	//
	// Clean up
	//

	delete[] encrypted_data;
	delete[] nonce;

	return true;
}

void STCP::Server::HandleClient( SOCKET client_socket, Server* server )
{
	Packet init_packet( Packet::INIT );
	init_packet.m_Data[0] = INIT_KEY;
	init_packet.m_Header.Size = 1;

	key_pair client_key_pair = { 0 };

	//
	// Send the server's public key to the client
	//

	if ( send( client_socket, (char*)&server->m_KeyPair.public_key, sizeof( server->m_KeyPair.public_key ), 0 ) == SOCKET_ERROR )
	{
		std::printf( "send failed: %d\n", WSAGetLastError( ) );
		goto exit;
	}

	//
	// Receive the client's public key and add it to the map
	//

	if ( recv( client_socket, (char*)&client_key_pair.public_key, sizeof( client_key_pair.public_key ), 0 ) == SOCKET_ERROR )
	{
		std::printf( "recv failed: %d\n", WSAGetLastError( ) );
		goto exit;
	}

	server->m_KeyMap[client_socket] = client_key_pair;

	if ( !server->Send( client_socket, init_packet ) )
		goto exit;

	while ( true )
	{
		Packet packet;

		if ( !server->Recv( client_socket, &packet ) )
			break;

		server->m_Handler( packet, server, client_socket );
	}

exit:
	server->m_KeyMap.erase( client_socket );
	closesocket( client_socket );
}

STCP::Client::Client( Config config ) : m_Config( config )
{
	if ( sodium_init( ) == -1 )
	{
		throw std::exception( "Failed to initialize sodium." );
	}

	if ( WSAStartup( MAKEWORD( 2, 2 ), &m_WSAData ) != 0 )
	{
		throw std::exception( "Failed to initialize Winsock." );
	}

	m_ConnectSocket = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

	struct addrinfo* result = NULL, * ptr = NULL, hints;

	ZeroMemory( &hints, sizeof( hints ) );
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if ( getaddrinfo( m_Config.IP, std::to_string( m_Config.Port ).c_str( ), &hints, &result ) != 0 )
	{
		throw std::exception( "Failed to get address info." );
	}

	for ( ptr = result; ptr != nullptr; ptr = ptr->ai_next )
	{
		m_ConnectSocket = socket( ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol );
		if ( connect( m_ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen ) )
		{
			throw std::exception( "Failed to connect to server." );
		}
		break;
	}

	if ( crypto_box_keypair( m_KeyPair.public_key, m_KeyPair.secret_key ) == -1 )
	{
		throw std::exception( "Failed to generate key pair." );
	}

	int iResult = recv( m_ConnectSocket, (char*)&m_ServerKP.public_key, sizeof( m_ServerKP.public_key ), 0 );

	if ( iResult == SOCKET_ERROR )
	{
		throw std::exception( "Failed to receive server key." );
	}

	if ( iResult != crypto_box_PUBLICKEYBYTES )
	{
		throw std::exception( "Received invalid server key." );
	}

	if ( send( m_ConnectSocket, (char*)&m_KeyPair.public_key, sizeof( m_KeyPair.public_key ), 0 ) == SOCKET_ERROR )
	{
		throw std::exception( "Failed to send client key. " );
	}

	Packet InitPacket;
	if ( !Recv( &InitPacket ) )
	{
		throw std::exception( "Failed to receive confirmation packet." );
	}

	if ( InitPacket.m_Header.ID != Packet::INIT || InitPacket.m_Data[0] != INIT_KEY )
	{
		//
		// TODO: Handle this
		//
	}
}