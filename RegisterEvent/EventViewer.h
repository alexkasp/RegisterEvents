#pragma once

#include <boost\asio.hpp>

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

