#include "svf-af.h"

/*
 * Server implementation helpers
 */
void sigchld_handler(int s) {
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/* 
 * Misc helpers
 */

// Dumps all the allowlisted function ID's to the given file
void dump_ids(std::string filename, std::set<uint32_t> allowed_ids) {
    ofstream ids_file;
    ids_file.open (filename, ios::out | ios::trunc);
    if (! ids_file.is_open()) {
        spdlog::critical("could not open indirect file..exiting");
        abort();
    }
    else {
        for (auto it=allowed_ids.begin(); it != allowed_ids.end(); ++it) { 
            ids_file << *it << "\n";
        }
        ids_file.close();
    }
}

// Dumps number of allowlisted functions and the number of indirect edges discovered during dynamic analysis
void dump_num(std::string filename, std::size_t allowlisted, std::size_t allowed_indir) {
    ofstream stats_file;
    stats_file.open (filename, ios::out | ios::app);
    if (! stats_file.is_open()) {
        spdlog::critical("could not open indirect file..exiting");
        abort();
    }
    else {
        stats_file << "Allowlisted:" << allowlisted << " Indirect:" << allowed_indir << "\n";
        stats_file.close();
    }
}

/*
 * Fencing helpers
 */
int64_t get_edge_id(uint32_t caller, uint32_t callee) {
    int64_t id = (int64_t) caller << 32 | callee;
    // Check to ensure that overflow has not occurred while creating this unique id
    if (id < 0) {
        printf("\nOverflow detected during edge ID creation");
        exit(1);
    }
    return id; 
}

std::string get_func_name(std::map<uint32_t, std::set<std::string>>& idxmap, uint32_t idx) {
    if (idxmap[idx].size() > 1)
        spdlog::debug("More than one function for Idx:{}", idx); 
    return *(idxmap[idx].begin());
}

PTACallGraphNode* get_callgraph_node(
        SVFModule* svfModule, 
        PTACallGraph* callgraph, 
        std::string target) {

    const Function *target_function = NULL;
    for (SVFModule::llvm_const_iterator I = svfModule->llvmFunBegin(), E =
                svfModule->llvmFunEnd(); I != E; ++I) {
        if ((target.compare((*I)->getName().str())) == 0) { 
	        target_function = *I;
            break;
        }
    }
    const SVFFunction* target_svf = svfModule->getSVFFunction(target_function);
    PTACallGraphNode* target_node = callgraph->getCallGraphNode(target_svf);
    return target_node;
}

bool isReachable(
        const SVFFunction* srcFn, 
        const SVFFunction *dstFn, 
        PTACallGraph* callgraph, 
        std::set<uint64_t>& allowed_indirect,
        std::set<std::string>& inlined_funcs) {
    PTACallGraphNode* dstNode = callgraph->getCallGraphNode(dstFn);

    std::stack<const PTACallGraphNode*> nodeStack;
    NodeBS visitedNodes;
    nodeStack.push(dstNode);
    visitedNodes.set(dstNode->getId());
    // spdlog::debug("+++"); 
    while (nodeStack.empty() == false)
    {

        PTACallGraphNode* node = const_cast<PTACallGraphNode*>(nodeStack.top()); 
        // spdlog::info("Function:{}", (node->getFunction()->getLLVMFun()->getName().str()));
        nodeStack.pop();
        // spdlog::debug("{}", node->getFunction()->getLLVMFun()->getName().str()); 
        if (node->getFunction() == srcFn)
            return true;

        for (PTACallGraph::CallGraphEdgeConstIter it = node->InEdgeBegin(), eit = node->InEdgeEnd(); it != eit; ++it)
        {
            PTACallGraphEdge* edge = *it;
            // Check if there is at least one indirect edge between two functions and that the function has not been inlined
            // if ((edge->isIndirectCallEdge()) || (!(edge->isIndirectCallEdge()) && !(edge->isDirectCallEdge()))) {
            if (edge->isIndirectCallEdge() && (inlined_funcs.find((edge->getSrcNode()->getFunction()->getLLVMFun()->getName().str())) == inlined_funcs.end())) {
                // If there is an indirect edge, and its not been observed before, ignore this
                if (allowed_indirect.find(edge->edgeFlag) == allowed_indirect.end()) { 
                    continue ;
                }
            }
            if (visitedNodes.test_and_set(edge->getSrcID()))
                nodeStack.push(edge->getSrcNode());
        }
    }

    return false;
}

// Get SVF function corresponding to function name 
const Function* get_function(std::string functionName, SVFModule* svfModule) {
    const Function *function = NULL;
    for (SVFModule::llvm_const_iterator I = svfModule->llvmFunBegin(), E =
                svfModule->llvmFunEnd(); I != E; ++I) {
        // std::cout << target_function->getName().str() << " ";
        if ((functionName.compare((*I)->getName().str())) == 0) { 
	        function = *I;
            break;
        }
    }
    return function;
    // Get corresponding call graph node for the target function
    // return svfModule->getSVFFunction(function);
}
// Find the entry point of a function
const Instruction* get_inst(std::string functionName, SVFModule* svfModule) {
    const Function* function = get_function(functionName, svfModule);
    if (function) {
        const BasicBlock &BB = function->getEntryBlock();
        const Instruction *inst = BB.getTerminator(); 
        return inst;
    } else {
        return NULL;
    }
}

// Processes all the indirect call edge ID's 
void process_indirect_edgeids(std::string& metadata, std::set<uint64_t>& allowed_indirect) {
    std::stringstream ss(metadata);
    std::string token;
    char delim = ' ';
    // The first token corresponds to the indirect call edge
    // Add it to the list of allowed indirect call edges
    while (std::getline(ss, token, delim)) {
        allowed_indirect.insert(std::stoull(token));
        break;
    }
}

void process_indirect_callees(std::string& metadata, std::set<uint64_t>& allowed_indirect, std::set<std::string>& allowlist,
        const SVFFunction* target_svf, PTACallGraph* callgraph, SVFModule* svfModule) {
    std::stringstream ss(metadata);
    std::string token, callee_str;
    int count = 0;
    char delim = ' ';
    while (std::getline(ss, token, delim)) {
        // The first token corresponds to the indirect call edge
        // Add it to the list of allowed indirect call edges
        if (count == 0) {
	    allowed_indirect.insert(std::stol(token));
            count += 1;
        }
        // The second token corresponds to the caller string. We don't do anything with it as of now
        else if (count == 1) {
            count += 1;
        }
        // The second token corresponds to the callee string
        else {
            callee_str = token;
            count = 0;
        }
    }

    // Get the PTACallgraph node corresponding to the callee 
    PTACallGraphNode* callee_node = get_callgraph_node(svfModule, callgraph, callee_str);

    // Insert the callee of the indirect call into the allowlist 
    allowlist.insert(callee_node->getFunction()->getLLVMFun()->getName().str());

    // Insert all the descendants of the callee into the allowlist
    // getForwardDescendants(callee_node, target_svf, allowed_indirect, allowlist, callgraph); 
}


/* Debug Helpers */
void check_edge(SVFModule* svfModule, PTACallGraph* callgraph, std::string caller, std::string callee) { 
    PTACallGraphNode* caller_node = get_callgraph_node(svfModule, callgraph, caller);
    PTACallGraphNode* callee_node = get_callgraph_node(svfModule, callgraph, callee); 
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
    if (! calledge) { 
        spdlog::info("No edge exists");
    }
    else {
        if (calledge->isIndirectCallEdge()) {
            spdlog::info("Indirect edge exists");
        } else {
            spdlog::info("Direct edge exists");
        }
    }
}

std::string demangleString(const char* name) 
{
  int status = -1; 
  std::unique_ptr<char, void(*)(void*)> res { abi::__cxa_demangle(name, NULL, NULL, &status), std::free };
  return (status == 0) ? res.get() : std::string(name);
}
