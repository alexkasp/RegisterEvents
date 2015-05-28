#ifndef __linux__
#include <boost\thread.hpp>
#include <boost\regex.hpp>
#include <boost\date_time\gregorian\gregorian.hpp>
#else
#include <boost/regex.hpp>
#include <boost/thread.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#endif

#include <stdlib.h>
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

int EventViewer::processOpensipsEvents()
{
    while(1)
    {
	char buff[1024];
	boost::asio::ip::udp::socket socket(io_service,boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 8080));
	boost::asio::streambuf buf;
	boost::system::error_code ec;
	boost::asio::ip::udp::endpoint sender_endpoint;
	int bytes = socket.receive_from(boost::asio::buffer(buff),sender_endpoint);
	if(bytes>0)
	
	{
	    std::string msg(buff, bytes);
	    cout<<msg<<endl;
	}
    }
}

int EventViewer::start()
{
	boost::thread(boost::bind(&EventViewer::processOpensipsEvents,this));
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

void EventViewer::blockip(string host)
{
    string arg = "iptables -I fail2ban-opensips 1 -s "+host+" -j DROP";
    system(arg.c_str());
}

void EventViewer::unblockip(string host)
{
    string arg="iptables -D fail2ban-opensips -s "+host+" -j DROP";
    system(arg.c_str());
}

// this function parse data and get sip login and ip addr
string EventViewer::parseEventData(string eventData)
{
	cout<<"Start string:"<<"\n"<<eventData<<endl;
	eventData.erase(std::remove(eventData.begin(), eventData.end(), '\\'), eventData.end());
	
	boost::regex xRegExpr("(\\w+) .* Auth for (.*)@(.*) from (.*) cause (.*) retry (\\d+).*");
	boost::smatch xResults;

	bool parsed = boost::regex_match(eventData, xResults, xRegExpr , boost::match_default | boost::match_partial);
	
	cout << "receive:\n" << eventData << "\n parsestatus=" << parsed << endl;

	string host = xResults[4];
	string sipnum = xResults[2];
	string domain = xResults[3];
	string retry = xResults[6];
	string cause = xResults[5];
	string action = xResults[1];
	
	cout<<"host="<<host<<"\n"<<"sipnum="<<sipnum<<"\n"<<"domain="<<domain<<"\n"<<"retry="<<retry<<"\n"<<"action="<<action<<endl;
	
	if(cause!="1")
	{
	    auto t = proved_ip.find(host);
	    
	    if(t!=proved_ip.end())
	    {
		//this ip proved we do nothing
	    }	
	    else
	    {
		if(action=="ban")
		{
		    cout<<"trying to ban"<<endl;
		    blockip(host);
		}
		else
		{
		    cout<<"try to unban"<<endl;
		    unblockip(host);
		}    
		sendEvent("/api/ats/block?host="+host+"&sipnum="+sipnum+"&domain="+domain+"&retry="+retry+"&action="+action);
	    }
	    
	
	}
	else
	{
	    struct timeval now;
	    gettimeofday(&now,NULL);
	    
	    
	    proved_ip[host] = now.tv_sec;
	}
	    
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
