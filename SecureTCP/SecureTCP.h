/*
	(C) 2023 paging, All rights reserved.
*/

#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <string>
#include <unordered_map>
#include <thread>
#include <Windows.h>
#include <exception>
#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment (lib, "Ws2_32.lib")

#include <sodium.h>

#define INIT_KEY 0x69

namespace STCP
{
	struct Config
	{
		const char* IP;
		int Port;
	};

	struct key_pair
	{
		unsigned char public_key[crypto_box_PUBLICKEYBYTES];
		unsigned char secret_key[crypto_box_SECRETKEYBYTES];
	};
	
	class Packet
	{
	public:
		enum ID : unsigned __int8
		{
			INIT = 0x0,
			REQUEST = 0x1,
			RESPONSE = 0x2
		};

		Packet( ) = default;
		Packet( ID id ) : m_Header{ id, 0 }
		{
		}

	public:
		struct Header
		{
			ID m_ID;
			unsigned __int16 m_Size;
		} m_Header;

		unsigned char m_Data[1024];

	};

	class Server
	{
	public:

		Server(Config config);

		bool Send( SOCKET ClientSocket, Packet packet );
		bool Recv( SOCKET ClientSocket, Packet* packet );

	public:

		Config m_Config;

		WSADATA m_WSAData;
		SOCKET m_ListenSocket;

		key_pair m_KeyPair;

		bool m_Done = false;

	public:

		static void HandleClient(SOCKET ClientSocket, Server* Srv);

		std::unordered_map<SOCKET, key_pair> m_KeyMap;
	};

	class Client
	{
	public:

		Client(Config config);

		bool Send(Packet packet);
		bool Recv(Packet* packet);

	public:
		
		Config m_Config;

		WSADATA m_WSAData;
		SOCKET m_ConnectSocket;

		key_pair m_KeyPair;
		key_pair m_ServerKP;
	};
}