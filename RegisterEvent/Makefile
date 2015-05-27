default:
	export CFLAGS="$CFLAGS -O0 -fbuiltin -g"
	export CXXFLAGS="$CXXFLAGS -O0 -fbuiltin -g"
	g++ main.cpp EventViewer.cpp -o main -lpthread -std=c++0x -I /usr/local/boost/include/ -L /usr/local/boost/lib/ -Wl,-Bstatic -lboost_system -lboost_regex -lboost_thread -lboost_date_time -Wl,-Bdynamic -lm -lcurl -lrt
	
clean:
	rm -f ./test ./main ./thread ./logs ./serv