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

int EventViewer::parse(std::stringstream& ss,string& param,string& value)
{
    string msg;
    if(std::getline(ss,msg,'\n'))
    {
	size_t pos = 0;
	if((pos = msg.find(delimiter))!= std::string::npos)
	{
	    param = msg.substr(0, pos);
	    msg.erase(0, pos + delimiter.length());
	    value=msg;
	}
	else
	    return -1;

    }

}

int EventViewer::parseTryingRegister(std::stringstream& ss)
{

     struct timeval now;
     gettimeofday(&now,NULL);
     
     string param;
     string callid;
     string sourceIP;
     string uid;
     
     parse(ss,param,uid);
     parse(ss,param,sourceIP);
     parse(ss,param,callid);
     
     registerdata rd;
     
     rd.sourceIP=sourceIP;
     rd.regTime=now.tv_sec;
     rd.uid = uid.substr(0,UID_LENGTH);
     
     callidtoip[callid] = rd;
     
	 
    return 1;
}

int EventViewer::parseWrongRegister(std::stringstream& ss)
{
    struct timeval now;
    gettimeofday(&now,NULL);
    
    string param;
    string host;
    string callid;
    string uid;
    
    parse(ss,param,uid);
    parse(ss,param,host);
    parse(ss,param,callid);
    
    auto regs = callidtoip.find(callid);
    
    
    if(regs!=callidtoip.end())
    {
    
	auto t = proved_ip.find(host);
	
	if(t!=proved_ip.end())
	{
	}
	    
	if((t!=proved_ip.end())&&((t->second).uid==uid.substr(0,UID_LENGTH)))
	{
		//this ip proved we do nothing
	}	
	else
	{
	    registerdata rd;
	    rd.sourceIP=host;
	    rd.regTime = now.tv_sec;
	    rd.uid = uid.substr(0,UID_LENGTH);
	
	    auto addres = blockedip.find(host);
	    if(addres!=blockedip.end())
	    {
		if(((addres->second).trycount++)>MAX_TRYCOUNT)
		{
		    callidtoip.erase(regs);
		    sendEvent("/api/ats/block?host="+host+"&sipnum="+uid+"&action=ban");
		    blockip(host);
		}
	    }
	    else
	    {
		rd.trycount=1;
		blockedip[host]=rd;
		callidtoip.erase(regs);
		
	    }
	    
	}
	
    }
    else
    {
    
    }
}

int EventViewer::parseRegistered(std::stringstream& ss)
{
    struct timeval now;
    gettimeofday(&now,NULL);
    
    string param;
    string callid;
    string uid;

    parse(ss,param,uid);
    parse(ss,param,callid);
    
    
    auto regs = callidtoip.find(callid);
    
    if(regs!=callidtoip.end())
    {
	
	proved_ip[(regs->second).sourceIP] = regs->second;
	callidtoip.erase(regs);
    }
        
    return 1;
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
	    buff[bytes]=0;
	    std::stringstream ss(buff);
	    std::string msg;
	    std::getline(ss,msg,'\n');
	    
	    if(msg=="E_PEER_TRYING_REGISTER")
	    {
		parseTryingRegister(ss);
	    }
	    else if(msg=="E_PEER_REGISTERED")
	    {
		parseRegistered(ss);
	    }
	    else if(msg=="E_PEER_WRONG_REGISTER")
	    {
		parseWrongRegister(ss);
	    }
	    
	}
    }
}

int EventViewer::processUnBlock()
{
    while(1)
    {
	
	boost::this_thread::sleep( boost::posix_time::milliseconds(10000));
	struct timeval now;
	gettimeofday(&now,NULL);
    
	for(auto h=blockedip.begin();h!=blockedip.end();)
	{
	    if((now.tv_sec-(h->second).regTime) > BLOCK_TIMEOUT_SECONDS)
	    {
		unblockip(h->first);
		sendEvent("/api/ats/block?host="+(h->first)+"&sipnum="+(h->second).uid+"&action=unban");
		blockedip.erase(h++);
	    
	    }
	else
	    ++h;
	
	}
    }
}

int EventViewer::start()
{
	boost::thread(boost::bind(&EventViewer::processUnBlock,this));
	
	while(1)
	{
	    processOpensipsEvents();
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
		parseEventData(str);
	}
	
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
	eventData.erase(std::remove(eventData.begin(), eventData.end(), '\\'), eventData.end());
	
	boost::regex xRegExpr("(\\w+) .* Auth for (.*)@(.*) from (.*) cause (.*) retry (\\d+).*");
	boost::smatch xResults;

	bool parsed = boost::regex_match(eventData, xResults, xRegExpr , boost::match_default | boost::match_partial);
	

	string host = xResults[4];
	string sipnum = xResults[2];
	string domain = xResults[3];
	string retry = xResults[6];
	string cause = xResults[5];
	string action = xResults[1];
	
	
	if(cause!="1")
	{
	    auto t = proved_ip.find(host);
	    
	    if((t!=proved_ip.end())&&((t->second).uid==sipnum.substr(0,UID_LENGTH)))
	    {
		//this ip proved we do nothing
	    }	
	    else
	    {
		if(action=="ban")
		{
		    //blockip(host);
		}
		else
		{
		    //unblockip(host);
		}    
		sendEvent("/api/ats/block?host="+host+"&sipnum="+sipnum+"&domain="+domain+"&retry="+retry+"&action="+action);
	    }
	    
	
	}
	    
	return xResults[2];
}


// this function send prepared data to registration host
int EventViewer::sendEvent(string data)
{
	try{
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
