#include <list>
#include <string>
#include <cstring>
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <unistd.h>
#include <err.h>
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;
using namespace boost::algorithm;

//bool not_target(int instCompCnt, char *argv[], int argc) {
bool not_target(int instCompCnt, vector<string> argv, int argc) {
    for (int i = 0; i < argc - 1; i ++) {
        if (!strcmp(argv[i].c_str(), "-o")){
            for (int j = 0; j < instCompCnt; j++){
                if (strstr(argv[i+1].c_str(), argv[j+3].c_str()))
                    return true;
            }
        }
    }
    return false;
}

void run(list<string> &params) {
	char **args = (char **)malloc(sizeof(char *) * (params.size() + 1));
	if (!args)
		err(1, "failed to allocate memory");

	int i = 0;
	for(auto &arg : params) {
		args[i] = strdup(arg.c_str());
		i ++;
	}
	args[i] = NULL;
	//for(int j=0; j<i; j++)
	//	printf("%s ", args[j]);
	//printf("\n");
	execvp(args[0], args);
}

//makei -j CC="./bin/dfs-usp-gcc/g++ /path/userspace-kcov.o 1 non-instrumented-dirs"
int main(int argc, char *argv[]) {

	/*
	for(int i=0; i<argc; i++)
		printf("%s ", argv[i]);
	printf("\n");
	*/

	list<string> params;
	if(strstr(argv[0], "dfs-usp-g++"))
    	params.push_back("g++");
    else
    	params.push_back("gcc");

	if (argc < 2 || !strstr(argv[1], "ucov")){
		for(int i=1; i<argc; i++)
			params.push_back(argv[i]);
		run(params);
		return 0;	
	}

	vector<string> new_argv;
	for(int i=0; i<argc; i++){
		if(i == 1){
			size_t pos = 0;
			string space_delimiter = " ";
			std::string ops(argv[1]);
		    while ((pos = ops.find(space_delimiter)) != string::npos) {
        		new_argv.push_back(ops.substr(0, pos));
		        ops.erase(0, pos + space_delimiter.length());
    		}
			new_argv.push_back(ops);
		} else {
			new_argv.push_back(argv[i]);
		}
	}
	/*
	std::cout << "---------------" << std::endl;
	for (auto &i: new_argv) {
        std::cout << i << std::endl;
    }
	std::cout << "---------------" << std::endl;
	*/
    //fstream fout;
    //fout.open("dfs-gcc.log", fstream::out | std::fstream::app);
    //if (!fout) err(1, "failed to open a log");

    int instCompCnt = atoi(new_argv[2].c_str());
	//printf("instCompCnt %d %s\n", instCompCnt, new_argv[2].c_str());
    bool noInst = not_target(instCompCnt, new_argv, argc);

    if (!noInst) {
        //params.push_back(new_argv[1]); ///path/userspace-kcov.o
        params.push_back("-fsanitize-coverage=trace-pc");
		params.push_back("-fsanitize-coverage=trace-cmp");
    }

	int has_ucov = 0;
    for (int i=instCompCnt+3; i<new_argv.size(); i++){
		if (new_argv[i] == "lucov") {
			has_ucov = 1;
		}
		if(new_argv[i] != new_argv[1])
	        params.push_back(new_argv[i]);
    }

	if (!has_ucov) {
		params.push_back("-L/root/dfs-fuzzing");
		params.push_back("-lucov");
	}
	/*
    for (auto &i: params) {
        std::cout << " " << i;
    }
    std::cout << std::endl;
	*/
    run(params);

    return 0;
}
