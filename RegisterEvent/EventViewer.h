#pragma once

#ifndef __linux__
#include <boost\asio.hpp>
#else
#include <boost/asio.hpp>
#endif
using namespace std;

class EventViewer
{
	
	boost::asio::io_service io_service;
public:
	EventViewer();
	~EventViewer();
	int start();
protected:
	int processEvents(shared_ptr<boost::asio::ip::tcp::socket> socket);
};

