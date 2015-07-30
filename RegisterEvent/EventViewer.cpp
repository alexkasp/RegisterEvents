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
#include <fstream>
#include "EventViewer.h"




int EventViewer::loadProvedIP(HOSTPARAMS& list)
{
    ifstream file;
    file.open("/var/local/proved_ip.list");
    if(file.is_open())
    {
	string host;
	string uid;
	while(parse(file,host,uid))
	{
	    cout<<"HOST "<<host<<" uid= "<<uid<<endl;
	    list[host]=uid;
	}
	return 1;
    }
    return 0;
}

int EventViewer::saveProvedIP(std::string host,std::string uid)
{
    ofstream file;
    file.open("/var/local/proved_ip.list",std::fstream::out | std::fstream::app);
    if(file.is_open())
    {
	file<<host<<delimiter<<uid<<"\n";
	file.close();
	file.clear();
	return 1;
    }
    else
    {
	cout<<"ERROR OPEN FILE"<<endl;
    }
    
    return 0;
}

EventViewer::EventViewer()
{
	boost::asio::ip::tcp::resolver resolver(io_service);
	boost::asio::ip::tcp::resolver::query query(server, "80");

	boost::asio::ip::tcp::resolver::iterator iter = resolver.resolve(query);
	ep = *iter;
	
	loadProvedIP(proved_ip);

}


EventViewer::~EventViewer()
{
}

int EventViewer::parse(std::istream& ss,string& param,string& value)
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
	    return 1;
	}
	else
	    return -1;

    }
    return 0;

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
    // rd.uid = uid.substr(0,UID_LENGTH);
     rd.uid = uid;
     
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
    
    //cout<<"CHECK "<<callid<<" "<<host<<endl;
    
    if(regs!=callidtoip.end())
    {
    
	auto t = proved_ip.find(host);
	
	if(t!=proved_ip.end())
	{
	    //cout<<"IP ADDR  FOUND"<<endl;
	    
	    //for(auto x = proved_ip.begin();x!=proved_ip.end();++x)
	//	cout<<(x->first)<<endl;
	    
	    //cout<<(t->second).uid<<" transform to " <<(t->second).uid.substr(0,UID_LENGTH)<<" compare with "<<uid.substr(0,UID_LENGTH)<<endl;
	}
	    
	if
	(
	    (t!=proved_ip.end())&&
	    (
		    ((t->second).uid.substr(0,UID_LENGTH)==uid.substr(0,UID_LENGTH))||
		    ((t->second).uid=="0")
		
	    )
	)
	{
	    //cout<<"IN THIS IP WE TRUST"<<endl;
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
		    cout<<"BLOCK HOST "<<host<<endl;
		    (addres->second).blocked = 1;
		    callidtoip.erase(regs);
		    sendEvent("/api/ats/block?host="+host+"&sipnum="+uid+"&action=ban");
		    blockip(host);
		}
		else
		{
		    cout<<"ADD HOST "<<host<<" "<<(addres->second).trycount<<endl;
		    (addres->second).regTime = now.tv_sec;
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
	//cout<<"Add to proved ip "<<(regs->second).sourceIP<<endl;
	auto  newip = proved_ip.insert(std::pair<string,registerdata>((regs->second).sourceIP,uid));
	if(newip.second)
	{
	    
	    saveProvedIP((regs->second).sourceIP,uid.substr(0,UID_LENGTH));
	}
	else
	{
	    (newip.first)->second = regs->second;
	}
	
	callidtoip.erase(regs);
    }
        
    return 1;
}

int EventViewer::processOpensipsEvents()
{
    
	char buff[1024];
	boost::asio::ip::udp::socket socket(io_service,boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 8080));
	boost::asio::streambuf buf;
	boost::system::error_code ec;
	boost::asio::ip::udp::endpoint sender_endpoint;
	while(1)
	{
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
	    //
	    if((now.tv_sec-(h->second).regTime) > BLOCK_TIMEOUT_SECONDS)
	    {
		cout<<"UNBLOCK "<<(h->first)<<" check "<<now.tv_sec<<" "<<(h->second).regTime<<"  "<<(now.tv_sec-(h->second).regTime)<<endl;
		if((h->second).blocked==1)
		{
		    cout<<"START UNBLOCK"<<endl;
		    unblockip(h->first);
		    sendEvent("/api/ats/block?host="+(h->first)+"&sipnum="+(h->second).uid+"&action=unban");
		}
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
