#ifndef __linux__
#include <boost\thread.hpp>
#else

#include <boost/thread.hpp>
#endif

#include "EventViewer.h"


EventViewer::EventViewer()
{
	
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
	}
	
	cout << "release socket" << endl;
	socket->close();
	
	return 0;
		
	
}
