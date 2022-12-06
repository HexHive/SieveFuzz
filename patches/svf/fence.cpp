#include "svf-af.h"
using namespace llvm;
using namespace std;
using namespace SVF;

std::set<std::string> traverseBackwardsInsensitive(ICFG* icfg, const Instruction* inst) {
	ICFGNode* iNode = icfg->getBlockICFGNode(inst);
	FIFOWorkList<const ICFGNode*> worklist;
	std::set<const ICFGNode*> visited;
    std::set<std::string> visited_functions; // Holds the whitelist of functions
	worklist.push(iNode);

	/// Traverse along ICFG 
	while (!worklist.empty()) {
		const ICFGNode* vNode = worklist.pop();
		for (ICFGNode::const_iterator it = vNode->InEdgeBegin(), eit =
				vNode->InEdgeEnd(); it != eit; ++it) {
			ICFGEdge* edge = *it;
			ICFGNode* succNode = edge->getSrcNode();
			if (visited.find(succNode) == visited.end()) {
                std::cout << "Visited:" << succNode->getId() << "\n";
		        visited.insert(succNode);
				worklist.push(succNode);
                // Find the unvisited function name
                const SVFFunction* succFun = succNode->getFun();
                const Function* candidate = succFun->getLLVMFun();
                std::cout << candidate->getName().str() << " ";
                visited_functions.insert(candidate->getName().str());
			}
            else {
                std::cout << "Already visited:" << succNode->getId() ;
            }
		}
	}
    return visited_functions;
}

void traverseBackwardsFlowSensitive(
        ICFG* icfg, 
        const Instruction* inst, 
        PTACallGraph* callgraph,
        std::set<std::string>& allowlist,
        std::set<uint64_t>& allowed_indirect,
        std::set<std::string>& inlined_funcs) {

    ICFGNode* iNode = icfg->getBlockICFGNode(inst);
    const SVFFunction* targetFun = iNode->getFun();
    spdlog::info("Target function:{}", targetFun->getLLVMFun()->getName().str());

	FIFOWorkList<const ICFGNode*> worklist;
	// std::set<const ICFGNode*> visited;
	std::set<ICFGEdge*> visited;
	worklist.push(iNode);

	/// Traverse along ICFG 
	while (!worklist.empty()) {
		const ICFGNode* vNode = worklist.pop();
        const SVFFunction* vNodeFun = vNode->getFun();
        const Function* vFun = vNodeFun->getLLVMFun();

        // Check if the node has calls to library functions, if so add them to allowlist
        // This ends up being necessary in cases like CGC where certain functions were compiled with
        // our instrumentation but end up being used as shared libraries. Such functions will not 
        // be observed during our static analysis but will only have a stub call. Therefore, they need
        // to be identified and added to our allowlist
        if (SVFUtil::isa<CallBlockNode>(vNode)) {
		    for (ICFGNode::const_iterator it = vNode->OutEdgeBegin(), eit =
		    		vNode->OutEdgeEnd(); it != eit; ++it) {
                ICFGEdge* libEdge = *it;
                if (CallCFGEdge* dirCall = SVFUtil::dyn_cast<CallCFGEdge>(libEdge)) {
                    ICFGNode* libNode = libEdge->getDstNode();
                    // Validate that the dest Node has no outgoing edge 
                    if(! libNode->hasOutgoingEdge()) { 
                        const SVFFunction* prevFun = libNode->getFun();
                        const Function* candidate = prevFun->getLLVMFun();
                        spdlog::debug("Lib detected:{}", candidate->getName().str());
                        allowlist.insert(candidate->getName().str());
                    }
                }
            }
        }

        spdlog::debug("XXX");
        spdlog::debug("Worklist Function:{} Node:{}", vFun->getName().str(), vNode->getId());
		for (ICFGNode::const_iterator it = vNode->InEdgeBegin(), eit =
				vNode->InEdgeEnd(); it != eit; ++it) {

			ICFGEdge* edge = *it;
			ICFGNode* prevNode = edge->getSrcNode();

            // Find the (possibly) unvisited function name
            const SVFFunction* prevFun = prevNode->getFun();
            const Function* candidate = prevFun->getLLVMFun();
            spdlog::debug("===");
            if (SVFUtil::isa<IntraBlockNode>(prevNode))
                spdlog::debug("  Prev Function:{} Prev Node:{} Type:IntraBlock", candidate->getName().str(), prevNode->getId()); 
            else if (SVFUtil::isa<CallBlockNode>(prevNode))
                spdlog::debug("  Prev Function:{} Prev Node:{} Type:CallBlock", candidate->getName().str(), prevNode->getId()); 
            else if (SVFUtil::isa<RetBlockNode>(prevNode))
                spdlog::debug("  Prev Function:{} Prev Node:{} Type:RetBlock", candidate->getName().str(), prevNode->getId()); 
            else if (SVFUtil::isa<FunEntryBlockNode>(prevNode))
                spdlog::debug("  Prev Function:{} Prev Node:{} Type:FunEntry", candidate->getName().str(), prevNode->getId()); 
            else if (SVFUtil::isa<FunExitBlockNode>(prevNode))
                spdlog::debug("  Prev Function:{} Prev Node:{} Type:FunExit", candidate->getName().str(), prevNode->getId()); 

            if (visited.find(edge) == visited.end()) {
                spdlog::debug("Edge Source:{}", candidate->getName().str());
                // If the caller can reach target function only then add it to the worklist
                if(CallCFGEdge* dirCall = SVFUtil::dyn_cast<CallCFGEdge>(edge)) {
                    spdlog::debug("  Checking reachability between {} and {}", targetFun->getLLVMFun()->getName().str(),candidate->getName().str());
                    if (isReachable(prevFun, targetFun, callgraph, allowed_indirect, inlined_funcs)) {
                        spdlog::debug("  {} can be reached by {}", targetFun->getLLVMFun()->getName().str(), candidate->getName().str());
                        worklist.push(prevNode);
                        allowlist.insert(candidate->getName().str());
                    }
                }
                else {
                    spdlog::debug("  Adding non-call edge");
                    allowlist.insert(candidate->getName().str());
                    worklist.push(prevNode);
                }
                visited.insert(edge);
            }
            else {
                spdlog::debug("Already visited");
            }

       }
   }
}

/* Given a call graph node gets all its forward descendants */
void getForwardDescendants(
        PTACallGraphNode* target_node,
        const SVFFunction* target_svf,
        std::set<uint64_t>& allowed_indirect,
        std::set<std::string>& inlined_funcs,
        std::set<std::string>& allowlist,
        PTACallGraph* callgraph) {

        FIFOWorkList<PTACallGraphNode*> worklist_forward; // Worklist for doing the forward traversal
        std::set<PTACallGraphNode*> visited_cgnodes; // Visited nodes set to account for loops

        for (PTACallGraphEdge::CallGraphEdgeSet::iterator it = target_node->OutEdgeBegin();
               it != target_node->OutEdgeEnd(); ++it) {
           PTACallGraphEdge* edge = (*it); 
           PTACallGraphNode* dstNode = edge->getDstNode();
        
           // Get function name
           const SVFFunction* dstFun = dstNode->getFunction();
           const Function* candidate = dstFun->getLLVMFun();
        
           if (visited_cgnodes.find(dstNode) == visited_cgnodes.end()) {
                spdlog::debug("XXX");
                spdlog::debug("Checking reachability between {} and {}", target_svf->getLLVMFun()->getName().str(),candidate->getName().str());
                if (isReachable(target_svf, dstFun, callgraph, allowed_indirect, inlined_funcs)) {
                   spdlog::debug("{} can reach {}", target_svf->getLLVMFun()->getName().str(),candidate->getName().str());
                   allowlist.insert(candidate->getName().str());
                   worklist_forward.push(dstNode); 
                }
           }
           visited_cgnodes.insert(dstNode);
        }
        
        while (!worklist_forward.empty()) {
                    PTACallGraphNode* dst = worklist_forward.pop();
            for (PTACallGraphEdge::CallGraphEdgeSet::iterator it = dst->OutEdgeBegin();
                   it != dst->OutEdgeEnd(); ++it) {

                PTACallGraphEdge* edge = (*it); 
                PTACallGraphNode* dstNode = edge->getDstNode();
                if (visited_cgnodes.find(dstNode) == visited_cgnodes.end()) {
                    // Get function name
                    const SVFFunction* dstFun = dstNode->getFunction();
                    const Function* candidate = dstFun->getLLVMFun();
                    spdlog::debug("XXX");
                    spdlog::debug("Checking reachability between {} and {}", target_svf->getLLVMFun()->getName().str(),candidate->getName().str()); 
                    if (isReachable(dst->getFunction(), dstFun, callgraph, allowed_indirect, inlined_funcs)) {
                      spdlog::debug("{} can reach {}", target_svf->getLLVMFun()->getName().str(),candidate->getName().str());
                      allowlist.insert(candidate->getName().str());
                      worklist_forward.push(dstNode); 
                    }
                    visited_cgnodes.insert(dstNode);
                }
            }
        }
}


std::set<std::string> traverseCallGraph(
        PTACallGraph* callgraph, 
        PTACallGraphNode* target) {

	FIFOWorkList<PTACallGraphNode*> worklist_backward; // Worklist for doing the backwards traversal
    FIFOWorkList<PTACallGraphNode*> worklist_forward; // Worklist for doing the forward traversal
    std::set<PTACallGraphNode*> visited;
    worklist_backward.push(target);
    std::set<std::string> visited_functions; // Holds the allowlisted functions
	while (!worklist_backward.empty()) {

		PTACallGraphNode* dst = worklist_backward.pop();
        // Find all hard dependencies for the candidate and
        // - add them to the worklist
        // - add the functions to the allowlist 
        for (PTACallGraphEdge::CallGraphEdgeSet::iterator it = dst->InEdgeBegin();
               it != dst->InEdgeEnd(); ++it) {
           PTACallGraphEdge* edge = (*it); 
		   PTACallGraphNode* srcNode = edge->getSrcNode();

           if (visited.find(srcNode) == visited.end()) {

              // Get function name
              const SVFFunction* srcFun = srcNode->getFunction();
              const Function* candidate = srcFun->getLLVMFun();
              
              worklist_backward.push(srcNode);
              visited_functions.insert(candidate->getName().str());
              visited.insert(srcNode);
           }
        }

        // Find all soft dependencies and
        // - add the functions to the allowlist
        // - Recursively add their children to the allowlist
        for (PTACallGraphEdge::CallGraphEdgeSet::iterator it = dst->OutEdgeBegin();
               it != dst->OutEdgeEnd(); ++it) {
           PTACallGraphEdge* edge = (*it); 
		   PTACallGraphNode* dstNode = edge->getDstNode();

              // Get function name
              const SVFFunction* dstFun = dstNode->getFunction();
              const Function* candidate = dstFun->getLLVMFun();

              visited_functions.insert(candidate->getName().str());
              worklist_forward.push(dstNode); 
           }

        // Recursively add all children of soft dependencies.
        while (!worklist_forward.empty()) {

		    PTACallGraphNode* dst = worklist_forward.pop();
            for (PTACallGraphEdge::CallGraphEdgeSet::iterator it = dst->OutEdgeBegin();
                   it != dst->OutEdgeEnd(); ++it) {
               PTACallGraphEdge* edge = (*it); 
		       PTACallGraphNode* dstNode = edge->getDstNode();
               if (visited.find(dstNode) == visited.end()) {
                  // Get function name
                  const SVFFunction* dstFun = dstNode->getFunction();
                  const Function* candidate = dstFun->getLLVMFun();

                  visited_functions.insert(candidate->getName().str());
                  visited.insert(dstNode);
                  worklist_forward.push(dstNode); 
               }
            }
        }
    }

    return visited_functions;
}


std::set<std::string> findReachableFunctions(
        SVFModule* svfModule,
        PTACallGraph* callgraph
        ) {

    std::set<std::string> reachable_functions; // Holds the allowlisted functions
    for (SVFModule::llvm_const_iterator F = svfModule->llvmFunBegin(), E =
        svfModule->llvmFunEnd(); F != E; ++F) {
        const SVFFunction* fun = svfModule->getSVFFunction(*F);
        if ((callgraph->getCallGraphNode(fun))->isReachableFromProgEntry()) {
            reachable_functions.insert((*F)->getName().str()); 
        }
    }
    return reachable_functions;
}

