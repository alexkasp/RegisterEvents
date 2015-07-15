#pragma once

#ifndef __linux__
#include <boost\asio.hpp>
#else
#include <boost/asio.hpp>
#endif

#include <sys/time.h>
#include <map>
#include <iostream>

using namespace std;

struct registerdata
{
    string sourceIP;
    time_t regTime;
    string uid;
    int trycount = 0;
};

class EventViewer
{
	const string server = "sipuni.com";
	boost::asio::ip::tcp::endpoint ep;
	boost::asio::io_service io_service;
	
	void blockip(string host);
	void unblockip(string host);
	int parseTryingRegister(stringstream& ss);
	int parseRegistered(stringstream& ss);
	int parseWrongRegister(stringstream& ss);
	
public:
	EventViewer();
	~EventViewer();

	// this function parse data and get sip login and ip addr
	string parseEventData(string eventData);
	int start();
protected:
	
	map<string,registerdata> proved_ip;
	map<string,registerdata> callidtoip;
	map<string,registerdata> blockedip;
	
	const string delimiter = "::";
	const int UID_LENGTH = 6;
	const int BLOCK_TIMEOUT_SECONDS=30;
	const int MAX_TRYCOUNT = 3;
	
	int parse(std::stringstream&, std::string&, std::string&);
	int processOpensipsEvents();
	int processEvents(shared_ptr<boost::asio::ip::tcp::socket> socket);
	int processUnBlock();
	
public:
	// this function send prepared data to registration host
	int sendEvent(string data);
};

