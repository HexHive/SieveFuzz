//===- svf-ex.cpp -- A driver example of SVF-------------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013->  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===-----------------------------------------------------------------------===//

/*
 // A driver program of SVF including usages of SVF APIs
 //
 // Author: Yulei Sui,
 */

#include "svf-af.h"

using namespace llvm;
using namespace std;
using namespace SVF;

static llvm::cl::opt<std::string> InputFilename(cl::Positional,
        llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));

// Specify the target function for directed fuzzing
static llvm::cl::opt<std::string> TargetFunction("f", llvm::cl::desc("Specify target function"), llvm::cl::value_desc("function name"));

// Specify the port 
static llvm::cl::opt<std::string> Port("p", llvm::cl::desc("Specify port"), llvm::cl::value_desc("Prt for static analysis server"));

// Specify activation file for the fuzz target 
static llvm::cl::opt<std::string> ActivationFile("activation", llvm::cl::desc("Specify activation file containing activation policy for all functions"), llvm::cl::value_desc("Activation file"));

// // Specify output file for allow-listed functions
// static llvm::cl::opt<std::string> OutputFile("indirect", llvm::cl::desc("Specify outfile for allowlisted functions"), llvm::cl::value_desc("Output file"));
// Specify tag to be used for all auxiliary files that are created 
static llvm::cl::opt<std::string> Tag("tag", llvm::cl::desc("Specify tag to be used for all auxiliary files"), llvm::cl::value_desc("Tag to be used as prefix for auxiliary files"));
static llvm::cl::opt<bool> dumpStats("dump-stats", llvm::cl::init(false), llvm::cl::desc("Switch to enable dumping stats relevant to the analysis"));

// Switch to perform reachability analysis on call graph to identify all reachable functions from entry point
static llvm::cl::opt<bool> GetReachable("get-reachable", llvm::cl::init(false), llvm::cl::desc("Perform reachability analysis on call graph")); 

// Switch to find viable functions to target with AreaFuzz
static llvm::cl::opt<bool> GetFeasible("get-feasible", llvm::cl::init(false), llvm::cl::desc("Perform feasibility analysis on fuzz target")); 

// Switch to perform reachability analysis on call graph to identify all reachable functions from entry point
static llvm::cl::opt<bool> GetInit("get-init", llvm::cl::init(false), llvm::cl::desc("perform analysis that gives initial list of allowlisted functions")); 

// Run the server in debug mode where we can query some specific aspects about the bitcode
static llvm::cl::opt<bool> Debug("debug", llvm::cl::init(false), llvm::cl::desc("Run module in debug mode")); 

// Switch to perform perform more accurate indirecct call resolution
static llvm::cl::opt<bool> GetIndirect("get-indirect", llvm::cl::init(false), llvm::cl::desc("Perform finer grained indirect call resolution")); 

// Switch to enable the static analysis to be run in client-server mode with the fuzzer as the client 
static llvm::cl::opt<bool> RunServer("run-server", llvm::cl::init(false), llvm::cl::desc("run static analysis server for interfacing with fuzzer")); 

int main(int argc, char ** argv) {

    int arg_num = 0;
    char **arg_value = new char*[argc];

    // Server-specific local variables
    int sockfd, new_fd, numbytes;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;
    // XXX:Measure the time taken to build the ICFG and CG
    auto start = chrono::steady_clock::now(); 

    std::vector<std::string> moduleNameVec;
    SVFUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    cl::ParseCommandLineOptions(arg_num, arg_value,
                                "Whole Program Points-to Analysis\n");
    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

    // Set logging level
    // spdlog::set_level(spdlog::level::debug);
    spdlog::cfg::load_env_levels();

    PAGBuilder builder;
    PAG* pag = builder.build(svfModule);

    Andersen* ander = AndersenWaveDiff::createAndersenWaveDiff(pag);

    /// Call Graph
    PTACallGraph* callgraph = ander->getPTACallGraph();

    spdlog::info("Performing electrification");

    // ICFG
    ICFG* icfg = pag->getICFG();
    // Updating ICFG with indirect call resolution
    if (GetIndirect) {
        icfg->updateCallGraph(callgraph);
    }
    auto end = chrono::steady_clock::now(); 
    spdlog::info("Time taken to build structures:{}", chrono::duration_cast<chrono::milliseconds>(end - start).count());

    // Get the port to run the static analysis server on
    std::string port = Port;

    // Create names for auxiliary names based on passed tag
    std::string indir_suffix = "_indirect";
    std::string stats_suffix = "_stats";
    std::string fnindices_suffix = "_fnindices";
    std::string log_suffix = "_log";
    std::string indir_file = Tag + indir_suffix;
    std::string stats_file = Tag + stats_suffix;
    std::string fnindices_file = Tag + fnindices_suffix;
    std::string log_file = Tag + log_suffix;
    try {
        auto logger = spdlog::basic_logger_mt("basic_logger", log_file);
        spdlog::set_default_logger(logger);
        spdlog::flush_on(spdlog::level::info);
    }
    catch (const spdlog::spdlog_ex &ex) {
        std::cout << "Log init failed: " << ex.what() << std::endl;
    }

    // Find the target function
    std::string target = TargetFunction; 

    // for (SVFModule::llvm_const_iterator I = svfModule->llvmFunBegin(), E =
    //             svfModule->llvmFunEnd(); I != E; ++I) {
    //     // std::cout << target_function->getName().str() << " ";
    //     if ((target.compare((*I)->getName().str())) == 0) { 
	//         target_function = *I;
    //         break;
    //     }
    // }


    // Get the Function corresponding to the target
    const Function* target_function = get_function(target, svfModule);

    // Ensure that the target function is present in the binary
    if (target_function == NULL) {
        std::cout << "No match found...exiting";
        exit(1);
    }

    // Get the SVF Function
    const SVFFunction* target_svf = svfModule->getSVFFunction(target_function);
    PTACallGraphNode* target_node = callgraph->getCallGraphNode(target_svf);
    // Find the entry point to the function
    const Instruction *inst = get_inst(target, svfModule);
    // const BasicBlock &BB = target_function->getEntryBlock();
    // const Instruction *inst = BB.getFirstNonPHI(); 


    // Algorithm:
    // edge_id = get_edge_id(caller, callee);
    // // Don't need to check edge has been previously processed because only unique
    // // previously unseen edges will be passed off from the fuzzer to this module
    // // if (edge_id in seen): 
    // //   break
    // caller_ptagraph_node = get_graph_node(caller);
    // callee_ptagraph_node = get_graph_node(calleee);
    // ptagraph_edge = get_graph_edge(caller_ptagraph_node, callee_ptagraph_node);
    // if (!ptagraph_edge)
    //   raise("TODO: Implement functionality to add a new edge");
    // ptagraph_edge_id = ptagraph_edge->get_edge_flag
    // allowlist.insert(ptagraph_edge_id)
    //
    // //perform fencing analysis
    // //see if any new functions added, if so send those function ids back to fuzzer

    // Check if the module is being run in server mode to interface with the fuzzer
    if (RunServer) {
       
        const Function* entryFuncLLVM = get_function("main", svfModule);
        const SVFFunction* entryFunc = svfModule->getSVFFunction(entryFuncLLVM);
        
        //XXX: The reason we decided to make two separate structures encoding the
        // same information because memory is cheap and I wanted to make accessing this
        // information O(1) 
        //
        // The reason why we keep a set as "value" in map because there are certain
        // functions (eg. main) that are compiled multiple times during the build process
        // and as such there are multiple indices associated with such functions.
        // I've put in this just as a sanity check to ensure duplicated functions are flagged
        //
        //
        // Create a map with key from function name to compile-time index
        // This map is used while creating response message to fuzzer to identify
        // indices to send corresponding to allowlisted functions
        std::map<std::string, std::set<uint32_t>> fun_to_idx_map; 
        // Create a map from index to function name. This is used while trying to identify
        // new edges to allowlist from info received from fuzzer 
        std::map<uint32_t, std::set<std::string>> idx_to_fun_map; 
        // Create a set of inlined functions in the fuzz target. This will be used to ignore functions
        // during static analysis on the BITCODE variant to ensure correctness of analysis
        std::set<std::string> inlined_funcs;
        

        std::ifstream file(ActivationFile);
        if (! file.is_open()) {
            spdlog::critical("Could not open Activation File exiting");
            abort();
        }
        else {
            std::string line;
            int idx = 0;
            while (std::getline(file, line)) {
                std::size_t pos_name = line.find("::");
                std::size_t pos_idx = line.find_last_of(":");
                std::string name = line.substr(pos_name + 2, pos_idx - pos_name - 2);
                uint32_t idx = (uint32_t) std::stoi(line.substr(pos_idx + 1));
                spdlog::info("Key:{} Val:{}", name, idx);
                fun_to_idx_map[name].insert(idx);
                idx_to_fun_map[idx].insert(name);
            }
            
            // Iterate through the fun_to_idx_map to identify functions for
            // which multiple indices exist (due to duplication across multiple CU)
            for (auto const& x: fun_to_idx_map) {
                if (x.second.size() > 1) {
                    spdlog::warn("{} has {} indices", x.first, x.second.size());
                }
            }
                
            file.close();
        }
        // Build a list of uninlined functions
        std::set<std::string> uninlined_funcs;
	for (auto const& x: fun_to_idx_map) {
		uninlined_funcs.insert(x.first);
	} 
        // Create a list of inlined functions by iterating through the functions of statically analyzed binary
        for (SVFModule::llvm_const_iterator I = svfModule->llvmFunBegin(), E =
                    svfModule->llvmFunEnd(); I != E; ++I) {
	    if (uninlined_funcs.find((*I)->getName().str()) == uninlined_funcs.end()) {
               spdlog::info("Inlined:{}", (*I)->getName().str());
	       inlined_funcs.insert((*I)->getName().str());
            }
        }

        // Check the set of reachable functions 
        if (GetReachable) {
            spdlog::info("Performing reachability analysis on callgraph");
            auto reachable_functions = findReachableFunctions(svfModule, callgraph); 
            ofstream myfile ("reachable_functions.txt");
            if (! myfile.is_open()) {
                std::cout << "Could not open output file exiting";
                exit(1);
            }
            for (auto it=reachable_functions.begin(); it != reachable_functions.end(); ++it) { 
                myfile << *it << "\n";
            }
            myfile.close();
            exit(0);
        }

        // Check if the static analysis module is being run in get-init mode
        if (GetInit) {
            std::set<std::string> allowlist;
            std::set<uint64_t> allowed_indirect;
            std::set<uint32_t> allowed_ids;
            if (isReachable(entryFunc, target_svf, callgraph, allowed_indirect, inlined_funcs)) {
                spdlog::info("Target function is reachable from entry point");
            }
            else {
                spdlog::info("Target function is not reachable from entry point");
            }
            spdlog::info("Performing analysis to infer initial list of allowlisted functions without resolving indirect calls");
            // Get the allowlist and send it back to the fuzzer
            // XXX: Measure the time taken to run the analysis
    	    auto start = chrono::steady_clock::now(); 
            traverseBackwardsFlowSensitive(icfg, inst, callgraph, allowlist, allowed_indirect, inlined_funcs);
            // spdlog::info("Allowlist_init:{}", allowlist.size());                        

            // getForwardDescendants(target_node, target_svf, allowed_indirect, inlined_funcs, allowlist, callgraph); 

            // spdlog::info("Allowlist_final:{}", allowlist.size());

            // Create the list of function ID's to be sent using names->idx map
            for (auto it=allowlist.begin(); it != allowlist.end(); ++it) { 
                spdlog::debug("Allowed_func:{}", (*it));
                allowed_ids.insert(fun_to_idx_map[*it].begin(), fun_to_idx_map[*it].end());
            }
            auto end = chrono::steady_clock::now(); 
            spdlog::info("Time taken to run analysis:{}", chrono::duration_cast<chrono::milliseconds>(end - start).count());
            spdlog::info("Allowed_ids:{}", allowed_ids.size());
            dump_ids("allowed_functions.txt", allowed_ids);
            exit(0);
        }

        // Check if the static analysis server is being run to perform feasibility analysis
        if (GetFeasible) {
            ofstream ids_file;
            spdlog::info("Performing feasibility analysis for the fuzz target");
            int32_t allowed_func_count;

            const SVFFunction* main_func = svfModule->getSVFFunction(get_function("main", svfModule));
            // Iterate through the coloring algo with each function as being the target
            for (SVFModule::llvm_const_iterator I = svfModule->llvmFunBegin(), E =
                        svfModule->llvmFunEnd(); I != E; ++I) {

                std::set<std::string> allowlist;
                std::set<uint64_t> allowed_indirect;
                std::set<uint32_t> allowed_ids;
                allowed_func_count = 0;
                
                spdlog::info("Mangled:{}", (*I)->getName().str());
                std::string functionName = demangleString((*I)->getName().str().c_str());
                spdlog::info("Demangled_AF:{}", functionName);
                if (fun_to_idx_map.find(functionName) == fun_to_idx_map.end()) {
                        spdlog::info("Skipping");
                        continue; 
                }
                else {
                    std::set<uint32_t> val = fun_to_idx_map.at(functionName);
                    for (auto it = val.begin(); it != val.end(); ++it) {
                        spdlog::info("Found {} at:{}", functionName, *it);
                    }
                    if (! val.size()) {
                        spdlog::info("Skipping");
                        continue;
                    }
                    functionName = ((*I)->getName().str());
                }
                const SVFFunction* target_func = svfModule->getSVFFunction(get_function(functionName, svfModule));
                const Instruction* entryInst = get_inst(functionName, svfModule);

                if (!entryInst) {
                    spdlog::info("Skipping due to no Inst:{}", functionName);
                    continue;
                }

                PTACallGraphNode* target_node = callgraph->getCallGraphNode(target_func);

                traverseBackwardsFlowSensitive(icfg, entryInst, callgraph, allowlist, allowed_indirect, inlined_funcs);
                spdlog::info("Allowlist_init:{}", allowlist.size());                        
                // getForwardDescendants(target_node, target_func, allowed_indirect, inlined_funcs, allowlist, callgraph); 
                spdlog::info("Allowlist_final:{}", allowlist.size());

                // Create the list of function ID's to be sent using names->idx map
                for (auto it=allowlist.begin(); it != allowlist.end(); ++it) { 
                    spdlog::debug("Allowed_func:{}", (*it));
                    // The reason we do this is because: 1) The allowlist consists of library functions
                    // that are not indexed
                    if(fun_to_idx_map.count((*it)) > 0) { 
                        spdlog::debug("Present in fun_to_idx_map");
                        allowed_func_count += 1;
                        allowed_ids.insert(fun_to_idx_map[*it].begin(), fun_to_idx_map[*it].end());
                    }
                    else {
                        spdlog::debug("Not present in fun_to_idx_map");
                    }
                }

                ids_file.open ("feasible.txt", ios::out | ios::app);
                if (! ids_file.is_open()) {
                    spdlog::critical("could not open indirect file..exiting");
                    abort();
                }
                else {
                    if (isReachable(main_func, target_func, callgraph, allowed_indirect, inlined_funcs)) {
                        ids_file << functionName << " " << allowed_func_count << " Yes" << "\n";
                    }
                    else { 
                        ids_file << functionName << " " << allowed_func_count << " No" << "\n";
                    }
                    ids_file.close();
                }
            }
            exit(0);
        }

        if (Debug) {
            // check_edge(svfModule, callgraph, "messagePos", "prvTidyWriteChar");
            check_edge(svfModule, callgraph, "ParseAttrs", "ParseValue");
            exit(0);
        }

        // Create function index map
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        
        if ((rv = getaddrinfo(NULL, port.c_str(), &hints, &servinfo)) != 0) {
            spdlog::info("Failed getaddrinfo: {}", gai_strerror(rv));
            return 1;
        }

        for (p = servinfo; p != NULL; p = p->ai_next) {
            if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
                perror("server:socket");
                continue;
            }

            if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
                perror("setsockopt");
                exit(1);
            }

            if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                close(sockfd);
                perror("server:bind");
                continue;
            }

            break;
        }

        freeaddrinfo(servinfo);

        if (p == NULL) {
            spdlog::info("Server:failed to bind");
            exit(1);
        }

        if (listen(sockfd, BACKLOG) == 1) {
            perror("listen");
            exit(1);
        }

        sa.sa_handler = sigchld_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == 1) {
            perror("sigaction");
            exit(1);
        }

        spdlog::info("Server waiting for connections");

        while(1) {
            // Create an allowlist for allowed indirect call edge ID's 
            // These need to be read from a control file after each event loop iteration
            // since the child process might have updated the control file with new
            // allowlisted indirect call edges. Same for the allowlist which needs to be created
            // fresh after each request from the fuzzer
            std::set<uint64_t> allowed_indirect;
            std::set<std::string> allowlist;

            sin_size = sizeof their_addr;
            new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
            if (new_fd == -1) {
                perror("accept");
                continue;
            }

            inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
            spdlog::info("Server:got connection from {}", s);
            
            if (!fork()) {
                close(sockfd);
                std::set<uint32_t> allowed_ids; // Specifies the list of allowed function ID's
                uint32_t numedges = 0;
                uint32_t caller = 0;
                uint32_t callee = 0;
                int64_t edge_id = 0;

                char buf[MAXDATASIZE];
                
                // Receive mode of operation
                spdlog::info("Receiving mode of operation");
                if ((numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0)) == -1 ) {
                    perror("recv");
                    exit(1);
                }
                buf[numbytes] = '\0';
                spdlog::info("Received:{}", buf);
                
                // Running the server in init mode where we do not resolve any indirect
                // call edges and run the static analysis to get initial list of allowlisted
                // functions. If the target function is reachable with this allowlist then 
                // we return INIT_YES. If the target function is not reachable then we return
                // INIT_NO where the fuzzer is to be run in the calibration phase
                if (strcmp(buf, "INIT") == 0) { 
                    // Check if target is reachable from entry point without resolving any indirect calls
                    if (isReachable(entryFunc, target_svf, callgraph, allowed_indirect, inlined_funcs)) {
                        // Get the allowlist and send it back to the fuzzer
                        traverseBackwardsFlowSensitive(icfg, inst, callgraph, allowlist, allowed_indirect, inlined_funcs);
                        spdlog::info("Allowlist_init:{}", allowlist.size());                        

                        // getForwardDescendants(target_node, target_svf, allowed_indirect, inlined_funcs, allowlist, callgraph); 

                        spdlog::info("Allowlist_final:{}", allowlist.size());

                        // Create the list of function ID's to be sent using names->idx map
                        for (auto it=allowlist.begin(); it != allowlist.end(); ++it) { 
                            spdlog::debug("Allowed_func:{}", (*it));
                            allowed_ids.insert(fun_to_idx_map[*it].begin(), fun_to_idx_map[*it].end());
                        }
                        spdlog::info("Allowed_ids:{}", allowed_ids.size());
                        // Dump stats related to static analysis if requested 
                        if (dumpStats) {
                            dump_ids(fnindices_file, allowed_ids);
                            dump_num(stats_file, allowed_ids.size(), 0); 
                        }


                        if (send(new_fd, "YES!", 4, 0) == -1)
                        perror("send");

                        spdlog::info("Size of allowlist:{}", allowed_ids.size());
                        uint32_t allowed_funcs = htonl(allowed_ids.size());
                        if (send(new_fd, &allowed_funcs, sizeof(allowed_funcs), 0) == -1) {  
                            perror("send");
                        }
                        // Send all the allowed function ID's one by one
                        for (auto it=allowed_ids.begin(); it != allowed_ids.end(); ++it) { 
                            uint32_t func_id = htonl(*it);
                            spdlog::debug("Allowed_init:{}", *it );
                            if (send(new_fd, &func_id, sizeof(func_id), 0) == -1) {  
                                perror("send");
                            }
                        }

                    } else {
                        if (send(new_fd, "NOO!", 4, 0) == -1)
                        perror("send");
                    }
                }
                // Running the server in fuzz mode where we accept new observed calledges
                // to refine our analysis
                else if (strcmp(buf, "FUZZ") == 0) {
                    
                    std::ifstream indirect_file;
                    indirect_file.open(indir_file, ios::in);

                    if (! indirect_file.is_open()) {
                         spdlog::warn("No indirect file");
                    }
                    else {
                        std::string line;
                        while (std::getline(indirect_file, line)) {
                            process_indirect_callees(line, allowed_indirect, allowlist, target_svf, callgraph, svfModule);
                        }
                        indirect_file.close();
                    }
                    
                    spdlog::info("Received FUZZ message");
                    if ((numbytes = recv(new_fd, &numedges, sizeof(numedges), 0)) == -1) {
                       perror("recv"); 
                    }
               
                    // spdlog::info("New edges:{}", ntohl(numedges));
                    uint32_t recv_edges = ntohl(numedges);
                    spdlog::info("New edges:{}", recv_edges);
                    std::string caller_str, callee_str ;
                    
                    for (int x = 0; x < recv_edges; x++) {
                        
                         if ((numbytes = recv(new_fd, &caller, sizeof(caller), 0)) == -1) {
                            perror("recv"); 
                         }
                         if ((numbytes = recv(new_fd, &callee, sizeof(callee), 0)) == -1) {
                            perror("recv"); 
                         }

                         // Get caller and callee PTAGraph node
                         caller_str = get_func_name(idx_to_fun_map, ntohl(caller)); 
                         callee_str = get_func_name(idx_to_fun_map, ntohl(callee)); 
                         PTACallGraphNode* caller_node = get_callgraph_node(svfModule, callgraph, caller_str);
                         PTACallGraphNode* callee_node = get_callgraph_node(svfModule, callgraph, callee_str);
                         spdlog::debug("Caller:{} Callee:{}", caller_str, callee_str);

                         // If caller and callee are same, just continue
                         // XXX: The second conditions exists because there was en edge from
                         // two different mains in cxxfilt. Right now we are just ignoring it
                         // but might want to investigate this later.
                         if ((ntohl(caller) == ntohl(callee)) || (caller_str.compare(callee_str) == 0)) {
                             spdlog::warn("Caller and callee are same: {} {}..continuing", caller_str, callee_str);
                             continue;
                         }


                         // Get call graph edge corresponding to the two nodes (if it exists)
                         // This API takes a callSiteID but does not use it
                         PTACallGraphEdge *calledge = NULL;
                         for (PTACallGraphEdge::CallGraphEdgeSet::iterator it = caller_node->OutEdgeBegin();
                                it != caller_node->OutEdgeEnd(); ++it) {
                            PTACallGraphEdge* tempEdge = (*it); 
                            PTACallGraphNode* dstNode = tempEdge->getDstNode();
                            if (dstNode->getId() == callee_node->getId()) {
                                calledge = tempEdge; 
                                spdlog::debug("Found corresponding callgraph edge");
                                break;
                            }
                         }
                         // PTACallGraphEdge* calledge = callgraph->getGraphEdge(caller_node, callee_node, PTACallGraphEdge::CallRetEdge, NULL); 
                         if (! calledge) { 
                             spdlog::critical("No edge exists between {} and {}", caller_str, callee_str);
			     spdlog::debug("Adding destination edge to allowlist"); 
			     allowlist.insert(callee_str);
			     continue;
                             //XXX: Might need to deal with this later.
                             // if (! isReachable(caller_node->getFunction(), callee_node->getFunction(), 
                             //             callgraph, allowed_indirect)) {
                             //     spdlog::debug("{} cannot reach {} as per SVF", caller_str, callee_str);
                             //     // abort();
                             // }
                             //
                             // continue;
                         }
                         // Add edge ID to allowlist only if it has an indirect
                         // edge. We do this because we allow all direct call graph
                         // edges by default.
                         // The second conditional is added because of how
                         // CallgraphEdges are implemented in SVF. All edges between
                         // two nodes are abstracted as a single edge. Therefore, if
                         // an edge has both direct and indirect calls between them
                         // then the first check fails and we would identify it
                         // through the second check (neither a pure direct edge nor
                         // a pure indirect edge) 
                         // if ((calledge->isIndirectCallEdge()) || (!(calledge->isIndirectCallEdge()) && !(calledge->isDirectCallEdge()))) {
                         if (calledge->isIndirectCallEdge()) {
                             if (allowed_indirect.find(calledge->edgeFlag) == allowed_indirect.end()) {
                                 spdlog::info("Indirect edge exists..adding its descendants recursively to the allowlist");
                                 ofstream indirect_file;
                                 indirect_file.open (indir_file, ios::out | ios::app);
                                 if (! indirect_file.is_open()) {
                                     spdlog::critical("could not open indirect file..exiting");
                                     abort();
                                 }
                                 else {
                                     // The following information is pushed:
                                     // edgeFlag - unique call edge ID as assigned by SVF
                                     // caller_str, callee_str - endpoint function names which are used to identify which functions to 
                                     // add as part of the descendants of the indirect calls
                                     allowed_indirect.insert(calledge->edgeFlag);
                                     indirect_file << calledge->edgeFlag << " " << caller_str << " " << callee_str << "\n";
                                     indirect_file.close();
                                 }

                             }
                         }
                    } // End of for loop which processes new call edges

                    indirect_file.open(indir_file, ios::in);
                    if (! indirect_file.is_open()) {
                         spdlog::warn("No indirect file");
                    }
                    else {
                        std::string line;
                        while (std::getline(indirect_file, line)) {
                            process_indirect_callees(line, allowed_indirect, allowlist, target_svf, callgraph, svfModule);
                        }
                        indirect_file.close();
                    }
                     
                    // Traverse backwards
                    spdlog::info("Size of indirect list:{}", allowed_indirect.size());
                    traverseBackwardsFlowSensitive(icfg, inst, callgraph, allowlist, allowed_indirect, inlined_funcs);

                    // Add all descendants of the target node to our allowlist
                    // getForwardDescendants(target_node, target_svf, allowed_indirect, inlined_funcs, allowlist, callgraph); 

                    // Create the list of function ID's to be sent using names->idx map
                    for (auto it=allowlist.begin(); it != allowlist.end(); ++it) { 
                        allowed_ids.insert(fun_to_idx_map[*it].begin(), fun_to_idx_map[*it].end());
                    }
                    spdlog::info("Size of allowlist:{}", allowed_ids.size());
                    // Dump all the function ID's if requested 
                    if (dumpStats) {
                        dump_ids(fnindices_file, allowed_ids);
                        dump_num(stats_file, allowed_ids.size(), allowed_indirect.size()); 
                    }

                    // Send the number of allowed ID's first
                    uint32_t allowed_funcs = htonl(allowed_ids.size());
                    if (send(new_fd, &allowed_funcs, sizeof(allowed_funcs), 0) == -1) {  
                        perror("send");
                    }
                    // Send all the allowed function ID's one by one
                    for (auto it=allowed_ids.begin(); it != allowed_ids.end(); ++it) { 
                        uint32_t func_id = htonl(*it);
                        spdlog::debug("Allowed:{}", *it );
                        if (send(new_fd, &func_id, sizeof(func_id), 0) == -1) {  
                            perror("send");
                        }
                    }

                } // End of FUZZ mode

                // Fuzzer client is asking which calibration mode is to be run
                else if (strcmp(buf, "CALQ") == 0) {

                    // Fuzzer is asking what type of calibration strategy to run
                    spdlog::info("Received CALQ message");

                    // Tell the fuzzer that we are going to be using the strategy of activating all functions
                    if (send(new_fd, "ALL!", 4, 0) == -1)
                        perror("send");
                } // End of CALQ response

                else if (strcmp(buf, "CALA") == 0) {
                    // Receive the number of edges
                    if ((numbytes = recv(new_fd, &numedges, sizeof(numedges), 0)) == -1) {
                       perror("recv"); 
                    }
               
                    uint32_t recv_edges = ntohl(numedges);
                    spdlog::info("New edges:{}", recv_edges);
                    std::string caller_str, callee_str ;

                    // Read in the indirect call edge file
                    std::ifstream indirect_file;
                    indirect_file.open(indir_file, ios::in);
                    if (! indirect_file.is_open()) {
                         spdlog::warn("No indirect file");
                    }
                    else {
                        std::string line;
                        // First process the metadata to populate all allowed indirect call edges
                        while (std::getline(indirect_file, line)) {
                            process_indirect_edgeids(line, allowed_indirect);
                       }
                       indirect_file.close();
                    }
                    
                    for (int x = 0; x < recv_edges; x++) {
                        
                         if ((numbytes = recv(new_fd, &caller, sizeof(caller), 0)) == -1) {
                            perror("recv"); 
                         }
                         if ((numbytes = recv(new_fd, &callee, sizeof(callee), 0)) == -1) {
                            perror("recv"); 
                         }

                         // Get caller and callee PTAGraph node
                         caller_str = get_func_name(idx_to_fun_map, ntohl(caller)); 
                         callee_str = get_func_name(idx_to_fun_map, ntohl(callee)); 
                         PTACallGraphNode* caller_node = get_callgraph_node(svfModule, callgraph, caller_str);
                         PTACallGraphNode* callee_node = get_callgraph_node(svfModule, callgraph, callee_str);
                         spdlog::debug("Caller:{} Callee:{}", caller_str, callee_str);

                         // If caller and callee are same, just continue
                         // XXX: The second conditions exists because there was en edge from
                         // two different mains in cxxfilt. Right now we are just ignoring it
                         // but might want to investigate this later.
                         if ((ntohl(caller) == ntohl(callee)) || (caller_str.compare(callee_str) == 0)) {
                             spdlog::warn("Caller and callee are same: {} {}..continuing", caller_str, callee_str);
                             continue;
                         }


                         // Get call graph edge corresponding to the two nodes (if it exists)
                         // This API takes a callSiteID but does not use it
                         PTACallGraphEdge *calledge = NULL;
                         for (PTACallGraphEdge::CallGraphEdgeSet::iterator it = caller_node->OutEdgeBegin();
                                it != caller_node->OutEdgeEnd(); ++it) {
                            PTACallGraphEdge* tempEdge = (*it); 
                            PTACallGraphNode* dstNode = tempEdge->getDstNode();
                            if (dstNode->getId() == callee_node->getId()) {
                                calledge = tempEdge; 
                                spdlog::debug("Found corresponding callgraph edge");
                                break;
                            }
                         }
                         // PTACallGraphEdge* calledge = callgraph->getGraphEdge(caller_node, callee_node, PTACallGraphEdge::CallRetEdge, NULL); 
                         if (! calledge) { 
                             spdlog::critical("No edge exists between {} and {}", caller_str, callee_str);
                             //XXX: Might need to deal with this later.
                             continue;
                         }
                        
                         // Add the indirect edge to the allowlist
                         if (calledge->isIndirectCallEdge()) {

                             if (allowed_indirect.find(calledge->edgeFlag) == allowed_indirect.end()) {
                                 spdlog::info("Indirect edge exists..keeping it in the allowlist");
                                 ofstream indirect_file;
                                 indirect_file.open (indir_file, ios::out | ios::app);
                                 if (! indirect_file.is_open()) {
                                     spdlog::critical("could not open indirect file..exiting");
                                     abort();
                                 }
                                 else {
                                     // The following information is pushed:
                                     // edgeFlag - unique call edge ID as assigned by SVF
                                     // caller_str, callee_str - endpoint function names which are used to identify which functions to 
                                     // add as part of the descendants of the indirect calls
                                     allowed_indirect.insert(calledge->edgeFlag);
                                     indirect_file << calledge->edgeFlag << " " << caller_str << " " << callee_str << "\n";
                                     indirect_file.close();
                                 }

                             }
                         }
                } // Processed all edges

                indirect_file.open(indir_file, ios::in);
                if (! indirect_file.is_open()) {
                     spdlog::warn("No indirect file");
                }
                else {
                    std::string line;
                    while (std::getline(indirect_file, line)) {
                        process_indirect_callees(line, allowed_indirect, allowlist, target_svf, callgraph, svfModule);
                    }
                    indirect_file.close();
                }
                // Check if with the updated edges the target has become reachable
                if (isReachable(entryFunc, target_svf, callgraph, allowed_indirect, inlined_funcs)) {
                    // Get the allowlist and send it back to the fuzzer
                    traverseBackwardsFlowSensitive(icfg, inst, callgraph, allowlist, allowed_indirect, inlined_funcs);
                    spdlog::info("CAL: Allowlist_init:{}", allowlist.size());                        

                    // getForwardDescendants(target_node, target_svf, allowed_indirect, inlined_funcs, allowlist, callgraph); 

                    spdlog::info("CAL: Allowlist_final:{}", allowlist.size());

                    // Create the list of function ID's to be sent using names->idx map
                    for (auto it=allowlist.begin(); it != allowlist.end(); ++it) { 
                        spdlog::debug("CAL: Allowed_func:{}", (*it));
                        allowed_ids.insert(fun_to_idx_map[*it].begin(), fun_to_idx_map[*it].end());
                    }
                    spdlog::info("CAL: Allowed_ids:{}", allowed_ids.size());

                    if (send(new_fd, "YES!", 4, 0) == -1)
                    perror("send");

                    spdlog::info("CAL: Size of allowlist:{}", allowed_ids.size());
                    uint32_t allowed_funcs = htonl(allowed_ids.size());
                    if (send(new_fd, &allowed_funcs, sizeof(allowed_funcs), 0) == -1) {  
                        perror("send");
                    }
                    // Send all the allowed function ID's one by one
                    for (auto it=allowed_ids.begin(); it != allowed_ids.end(); ++it) { 
                        uint32_t func_id = htonl(*it);
                        spdlog::debug("CAL: Allowed_init:{}", *it );
                        if (send(new_fd, &func_id, sizeof(func_id), 0) == -1) {  
                            perror("send");
                        }
                    }
                }
                else {
                    if (send(new_fd, "NOO!", 4, 0) == -1)
                    perror("send");
                }
            } // end of CALA mode

            spdlog::info("Exiting child");
            close(new_fd);
            exit(0);
            } // End of child process
            close(new_fd);
      } // End of event loop
        return 0;
    }


    // Traverse backwards
    // auto functions = traverseBackwardsInsensitive(icfg, inst);
    // auto functions = traverseBackwards(icfg, inst, allowlist);
    // auto functions = traverseCallGraph(callgraph, target_node);
    //
    // std::set<uint64_t> allowed_indirect;
    // auto allowlist = traverseBackwardsFlowSensitive(icfg, inst, callgraph, allowed_indirect);

    // // Recursively Get all callsites for the target function and add them to the allowlist
    // // PTACallGraphEdge::CallInstSet csSet;
    // // callgraph->getAllCallSitesInvokingCallee(target_svf, csSet);
    // // // Iterate through the callsites and print their addr
    // // std::set<std::string> allowlist; // Holds the whitelist of allowed callsites 
    // // for (auto it = csSet.begin(); it != csSet.end(); ++it) {
    // //     std::string str;
    // //     raw_string_ostream rawstr(str);
    // //     rawstr << (*it)->getCallSite().getInstruction();
    // //     allowlist.insert(rawstr.str());
    // //     // std::cout << rawstr.str();
    // // }
    // for (PTACallGraphEdge::CallGraphEdgeSet::iterator it = target_node->OutEdgeBegin();
    //        it != target_node->OutEdgeEnd(); ++it) {
    //    PTACallGraphEdge* edge = (*it); 
	//    PTACallGraphNode* dstNode = edge->getDstNode();

    //    // Get function name
    //    const SVFFunction* dstFun = dstNode->getFunction();
    //    const Function* candidate = dstFun->getLLVMFun();

    //    allowlist.insert(candidate->getName().str());
    // }

    // 
    // ofstream myfile (OutputFile);
    // if (! myfile.is_open()) {
    //     std::cout << "Could not open output file exiting";
    //     exit(1);
    // }
    // for (auto it=allowlist.begin(); it != allowlist.end(); ++it) 
    //     myfile << *it << "\n";
    // myfile.close();

    return 0;
}

