#include "SVF-FE/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "Graphs/PTACallGraph.h"
#include "WPA/Andersen.h"
#include "spdlog/spdlog.h"
#include "spdlog/cfg/env.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "SVF-FE/PAGBuilder.h"
// #include "llvm-c/Core.h"
#include <iostream>
#include <fstream>
#include <cxxabi.h>
// Static-analysis specific 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <chrono>

// #define PORT "3490"
#define BACKLOG 10
#define MAXDATASIZE 5 

using namespace llvm;
using namespace std;
using namespace SVF;

/*Server helpers*/
void sigchld_handler(int);
void *get_in_addr(struct sockaddr *);

/*Fencing helpers*/
PTACallGraphNode* get_callgraph_node(SVFModule*, PTACallGraph*, std::string);
int64_t get_edge_id(uint32_t caller, uint32_t callee);
std::string get_func_name(std::map<uint32_t, std::set<std::string>>&, uint32_t);
const Function* get_function(std::string, SVFModule*);
const Instruction* get_inst(std::string, SVFModule*); 
void process_indirect_edgeids(std::string&, std::set<uint64_t>&);
void process_indirect_callees(std::string&, std::set<uint64_t>&, std::set<std::string>&, const SVFFunction*, PTACallGraph*, SVFModule*);

/*Misc helpers*/
void dump_ids(std::string, std::set<uint32_t>);
void dump_num(std::string, std::size_t, std::size_t);
std::string demangleString(const char* name);

/*Fencing prototypes*/
std::set<std::string> traverseBackwardsFlowInsensitive(ICFG*, const Instruction*, PTACallGraph*);
void traverseBackwardsFlowSensitive(ICFG*, const Instruction*, PTACallGraph*, std::set<std::string>&, std::set<uint64_t>&, std::set<std::string>&);
std::set<std::string> traverseCallGraph(PTACallGraph*, PTACallGraphNode*);
std::set<std::string> findReachableFunctions(SVFModule*, PTACallGraph*);
void getForwardDescendants(PTACallGraphNode*, const SVFFunction*, std::set<uint64_t>&, std::set<std::string>&, std::set<std::string>&, PTACallGraph*);
bool isReachable(const SVFFunction*, const SVFFunction*, PTACallGraph*, std::set<uint64_t>&, std::set<std::string>&);

/*Debug Helpers*/
void check_edge(SVFModule*, PTACallGraph*, std::string, std::string);


