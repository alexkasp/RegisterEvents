#pragma once

#ifndef __linux__
#include <boost\asio.hpp>
#else
#include <boost/asio.hpp>
#endif
using namespace std;

class EventViewer
{
	const string server = "sipuni.com";
	boost::asio::ip::tcp::endpoint ep;
	boost::asio::io_service io_service;
public:
	EventViewer();
	~EventViewer();

	// this function parse data and get sip login and ip addr
	string parseEventData(string eventData);
	int start();
protected:
	int processEvents(shared_ptr<boost::asio::ip::tcp::socket> socket);
	
	
public:
	// this function send prepared data to registration host
	int sendEvent(string data);
};

