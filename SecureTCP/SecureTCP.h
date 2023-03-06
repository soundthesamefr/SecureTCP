/*
	(C) 2023 paging, All rights reserved.

	GNU General Public License v3.0
*/

#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define INIT_KEY 0x29

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <exception>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_map>
#include <sodium.h>

#pragma comment (lib, "Ws2_32.lib")

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
		enum ID : uint8_t
		{
			INIT = 0x0
		};

		struct Header
		{
			ID ID;
			uint16_t Size;
		};

		Packet( ) = default;
		explicit Packet( ID id ) : m_Header{ id, 0 }, m_Data{ 0 }
		{
		}

		Header m_Header;
		unsigned char m_Data[1024];
	};

	class Server
	{
	public:
		Server( Config config, std::function<void( Packet&, Server*, SOCKET )> handler );

		bool Send( SOCKET client_socket, Packet packet );
		bool Recv( SOCKET client_socket, Packet* packet );

		void Stop( );

	public:
		Config m_Config;
		std::function<void( Packet&, Server*, SOCKET )> m_Handler;

	private:
		WSADATA m_WSAData;
		SOCKET m_ListenSocket;
		key_pair m_KeyPair;
		bool m_Done = false;

		std::unordered_map<SOCKET, key_pair> m_KeyMap;

	public:
		static void HandleClient( SOCKET client_socket, Server* srv );
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