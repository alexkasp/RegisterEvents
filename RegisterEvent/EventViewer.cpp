#ifndef __linux__
#include <boost\thread.hpp>
#include <boost\regex.hpp>
#include <boost\date_time\gregorian\gregorian.hpp>
#else
#include <boost/regex.hpp>
#include <boost/thread.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#endif

#include "EventViewer.h"


EventViewer::EventViewer()
{
	boost::asio::ip::tcp::resolver resolver(io_service);
	boost::asio::ip::tcp::resolver::query query(server, "80");

	boost::asio::ip::tcp::resolver::iterator iter = resolver.resolve(query);
	ep = *iter;

}


EventViewer::~EventViewer()
{
}


int EventViewer::start()
{
	boost::asio::ip::tcp::acceptor a(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 8080));
	while (1)
	{
		shared_ptr<boost::asio::ip::tcp::socket> socket(new boost::asio::ip::tcp::socket(io_service));
		a.accept(*socket);

		boost::thread(boost::bind(&EventViewer::processEvents,this,socket));
	}
	
	

	return 0;
}


int EventViewer::processEvents(shared_ptr<boost::asio::ip::tcp::socket> socket)
{
	boost::asio::streambuf buf;
	boost::system::error_code ec;
	boost::asio::read_until(*socket, buf, "\n", ec);
	
	if (!ec)
	{	
		string str(boost::asio::buffers_begin(buf.data()), boost::asio::buffers_begin(buf.data()) + buf.size());
		std::cout << "Receive Event" << str;
		parseEventData(str);
	}
	
	cout << "release socket" << endl;
	socket->close();
	
	return 0;
		
	
}


// this function parse data and get sip login and ip addr
string EventViewer::parseEventData(string eventData)
{
	cout<<"Start string:"<<"\n"<<eventData<<endl;
	eventData.erase(std::remove(eventData.begin(), eventData.end(), '\\'), eventData.end());
	
	//boost::regex xRegExpr(".*ban .* Auth error for (.*)@(.*) from (.*) cause .* retry (\\d+) .*");
	boost::regex xRegExpr("(\\w+) .* Auth error for (.*)@(.*) from (.*) cause .* retry (\\d+).*");
	//boost::regex xRegExpr(".* Auth error for (.*)@(.*) from .*");
	boost::smatch xResults;

	bool parsed = boost::regex_match(eventData, xResults, xRegExpr , boost::match_default | boost::match_partial);
	
	cout << "receive:\n" << eventData << "\n parsestatus=" << parsed << endl;

	string host = xResults[4];
	string sipnum = xResults[2];
	string domain = xResults[3];
	string retry = xResults[5];
	string action = xResults[1];
	
	cout<<"host="<<host<<"\n"<<"sipnum="<<sipnum<<"\n"<<"domain="<<domain<<"\n"<<"retry="<<retry<<"\n"<<"action="<<action<<endl;

	sendEvent("/api/ats/block?host="+host+"&sipnum="+sipnum+"&domain="+domain+"&retry="+retry+"&action="+action);
	//string result = xResults[1];
	return xResults[2];
}


// this function send prepared data to registration host
int EventViewer::sendEvent(string data)
{
	try{
		cout << "try send:\n" << data << endl;
		boost::asio::streambuf request;

		std::ostream request_stream(&request);

		request_stream << "GET " << data << " HTTP/1.0\r\n";
		request_stream << "Host: " << server << "\r\n";
		request_stream << "Accept: */*\r\n";
		request_stream << "Connection: close\r\n\r\n";

		boost::asio::ip::tcp::socket sock(io_service);
		sock.connect(ep);
		boost::system::error_code ec;
		boost::asio::write(sock, request);
		sock.close();

	}
	catch (exception& e)
	{
		cout << "CATCH EXCEPTION!!!" << e.what() << '\n';
	}
	return 0;
}
