#include <list>
#include <string>
#include <cstring>
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <unistd.h>
#include <err.h>
#include <iostream>
#include <fstream>

using namespace std;
using namespace boost::algorithm;

bool is_target(int instCompCnt, char *argv[], int argc) {
    for (int i = 0; i < argc - 1; i ++) {
        if (!strcmp(argv[i], "-o")){
            for (int j = 2; j <= instCompCnt+1; j++){
                if (strstr(argv[i+1], argv[j]))
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
  execvp(args[0], args);
}

//make -j CC="%s/../ff-gcc/ff-gcc fs/ceph"
int main(int argc, char *argv[]) {

    if (argc < 2) {
        err(1, "Not enought params for dfs-gcc\n");
    }

    fstream fout;
    fout.open("dfs-gcc.log", fstream::out | std::fstream::app);
    if (!fout) err(1, "failed to open a log");

    int instCompCnt = atoi(argv[1]);

    bool needInst = is_target(instCompCnt, argv, argc);

    list<string> params;
    params.push_back("gcc");

    for (int i=instCompCnt+2; i<argc; i++){
        //-fsanitize-coverage=trace-pc -fsanitize-coverage=trace-cmp
        if (!strcmp(argv[i], "-fsanitize-coverage=trace-pc") 
                || !strcmp(argv[i], "-fsanitize-coverage=trace-cmp")
                || !strcmp(argv[i], "-fsanitize=kernel-address")
                || strstr(argv[i], "-fasan-shadow-offset")){
            if (needInst){
                params.push_back(argv[i]);
            }
        } else {
            params.push_back(argv[i]);
        }
    }

    for (auto &i: params) {
        fout << " " << i;
    }
    fout << std::endl;

    run(params);

    return 0;
}
