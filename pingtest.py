from threading import Thread
from package.library import *
def tcpdumpcapture_validate_same_network(sourcevm, dstvm, srcvxlan, dstvxlan,\
                                         sourcevmports, dstvmports):
    print "Capturing tcpdump at tap port of source vm"
    srctapreq, srctaprep, srctapreqcnt, srctaprepcnt = requestandreplyparse(sourcevm['hostip']\
 						       +sourcevmports[-1]+sourcevm['mac']+'.txt')
    #print srctapreq
    print "Capturing tcpdump at qvb port of source vm"
    srcqvbreq, srcqvbrep, srcqvbreqcnt, srcqvbrepcnt = requestandreplyparse(sourcevm['hostip']\
					 	       +sourcevmports[1]+sourcevm['mac']+'.txt')
    print "Capturing tcpdump at qvo port of source vm"
    srcqvoreq, srcqvorep, srcqvoreqcnt, srcqvorepcnt = requestandreplyparse(sourcevm['hostip']\
						       +sourcevmports[2]+sourcevm['mac']+'.txt')
    print "Capturing tcpdump at vxlan port of source vm host"
    srcvxlanreq, srcvxlanrep, srcvxlanreqcnt, srcvxlanrepcnt = requestandreplyparse\
						               (sourcevm['hostip']+srcvxlan[0]+sourcevm['mac']+'.txt')
    dsttapreq, dsttaprep, dsttapreqcnt, dsttaprepcnt = requestandreplyparse(dstvm['hostip']\
  						       +dstvmports[-1]+dstvm['mac']+'.txt')
    print "Capturing tcpdump at qvb port of destination vm"
    dstqvbreq, dstqvbrep, dstqvbreqcnt, dstqvbrepcnt = requestandreplyparse(dstvm['hostip']\
						       +dstvmports[1]+dstvm['mac']+'.txt')
    print "Capturing tcpdump at qvo port of destination vm"
    dstqvoreq, dstqvorep, dstqvoreqcnt, dstqvorepcnt = requestandreplyparse(dstvm['hostip']\
						       +dstvmports[2]+dstvm['mac']+'.txt')
    print "Capturing tcpdump at vxlan port of destination vm host"
    dstvxlanreq, dstvxlanrep, dstvxlanreqcnt, dstvxlanrepcnt = requestandreplyparse(dstvm['hostip']\
							       +dstvxlan[0]+dstvm['mac']+'.txt')
    frstchksrctap = response_check(srctapreq, srctaprep, srctapreqcnt, srctaprepcnt)
    if frstchksrctap == "pass":
        print "ping test passed"
    else:
        sndchksrctap, reqssrctap = request_check(srctapreq, srctaprep, srctapreqcnt, srctaprepcnt)
        if sndchksrctap == "norequestandreply":
            ports = port_validation_src(sourcevm['hostip'])
            #print("There is no request and reply in the source tap port")
            if ports:
               #print ports
                print "Host  : ", ports[2]
                print "Port  : ", ports[0]['port_name'].strip('(').strip(')')
                print "Bridge: ", ports[1]
                print "Status: ", "DOWN"
            else:
                #print("No OVS ports are down on source host  checking physical connection"
                if port_validation_src(dstvm['hostip']):
                    ports1 = port_validation_src(dstvm['hostip'])
                    print "Host  : ", ports1[2]
                    print "Port  : ", ports1[0]['port_name'].strip('(').strip(')')
                    print "Bridge: ", ports1[1]
                    print "Status: ", "DOWN"
                elif sourcevm['host'] != dstvm['host'] and getphysicalportstate(sourcevm['hostip']):
                    print "Host  : ", sourcevm['hostip']
                    print "Port  : ", getphysicalportstate(sourcevm['hostip'])[0]
                    print "Status: DOWN"
                elif getphysicalportstate(dstvm['hostip']):
                    print "Host  : ", dstvm['hostip']
                    print "Port  : ", getphysicalportstate(dstvm['hostip'])[0]
                    print "Status: DOWN"
                else:
                    print "Check for iptables of source vm"
        elif (sndchksrctap == "noreply" and sourcevm['host'] != dstvm['host']):
            if frstchkdsttap == "pass":
                frstchkdstvxlan = response_check(dstvxlanreq, dstvxlanrep,\
				  dstvxlanreqcnt, dstvxlanrepcnt)
                if frstchkdstvxlan == "pass":
                    frschksrcvxlan = response_check(srcvxlanreq, srcvxlanrep, srcvxlanreqcnt, \
				     srcvxlanrepcnt)
                    if frschksrcvxlan == "pass":
                        frschksrcqvo = response_check(srcqvoreq, srcqvorep,\
			               srcqvoreqcnt, srcqvorepcnt)
                        if frschksrcqvo == "pass":
                            frschksrcqvb = response_check(srcqvbreq, srcqvbrep,\
                                           srcqvbreqcnt, srcqvbrepcnt)
                            if frschksrcqvb == "pass":
                                print "check for mac table of linux bridge as reply\
				       reaches the source qvb port but not the tap port"
                            else:
                                print "check for veth connection in source node as reply\
				      reaches the source qvo port but not the source qvb port"
                        else:
                            print "check  for ovs flow table of source node as reply\
				   reaches the source vxlan port but not the source qvo port"
                    else:
                        print "check Tunnel connection between destination and source node as reply\
			       reaches the destination vxlan port but not the source vxlan port"
                else:
                    frschkdstqvo = response_check(dstqvoreq, dstqvorep, dstqvoreqcnt, dstqvorepcnt)
                    if frschkdstqvo == "pass":
                        print "check for ovs flow table in dst node as reply reaches the\
                               destination qvo port but not the destination vxlan port"
                    else:
                        frschkdstqvb = response_check(dstqvbreq, dstqvbrep, \
                                                     dstqvbreqcnt, dstqvbrepcnt)
                        if frschkdstqvb == "pass":
                            print "check for veth connection in destination node as reply reaches \
                                   the destination qvb port but not the destination qvo port"
                        else:
                            print "check for mac  table of linux bridge in the destination node as\
                            reply reaches the destination tap port but not the qvb port"
            else:
                sndchkdsttap, reqssrctap = request_check(dsttapreq, \
                                           dsttaprep, dsttapreqcnt, dsttaprepcnt)
                if sndchkdsttap == "norequestandreply":
                    print "check for iptables of dst vm for both ingress and egress"
                    sndchkdstvxlan, reqssrctap = request_check(dstvxlanreq, dstvxlanrep, \
                                                 dstvxlanreqcnt, dstvxlanrepcnt)
                    if sndchkdstvxlan == "norequestandreply":
                        sndchksrcvxlan = request_check(srcvxlanreq, srcvxlanrep, \
                                         srcvxlanreqcnt, srcvxlanrepcnt)
                        if sndchksrcvxlan == "norequestandreply":
                            sndchksrcqvo, reqssrctap = request_check(srcqvoreq, srcqvorep, srcqvoreqcnt, srcqvorepcnt)
			    if sndchksrcqvo == "norequestandreply":
			        sndchksrcqvb, reqssrctap = request_check(srcqvbreq, srcqvbrep, srcqvbreqcnt, srcqvbrepcnt)
			        if sndchksrcqvb == "norequestandreply":
				    print "check for mac table of linux bridge as request is captured in\
                                            source tap but not in source qvb port"
			        elif sndchksrcqvb == "noreply":
				    print "check for veth connection as request is captured in\
                                           source qvb port but not in source qvo port"
			    elif sndchksrcqvo == "noreply":
			        print "check for ovs flow table of source vm host as request is captured in\
                                        source qvo port but not in the source vxlan port"
			elif sndchksrcvxlan == "noreply":
			    print "check for physical connection between source host and destination host as request is\
                                    captured in source host vxlan port but not in destination host vxlan port"
		    elif sndchkdstvxlan == "noreply":
		        sndchkdstqvo, reqssrctap = request_check(dstqvoreq, dstqvorep, dstqvoreqcnt, dstqvorepcnt)
                        if sndchkdstqvo == "noreply":
                            sndchkdstqvb, reqssrctap = request_check(dstqvbreq, dstqvbreqcnt, dstqvbrep, dstqvbrepcnt)
                            if sndchkdstqvb == "noreply":
                                print "check for mac table of linux bridge in dst node as request is\
                                       captured in destination qvb port but not in tap port"
                            elif sndchkdstqvb == "norequestandreply":
                                print "check for veth connection in dst node as request is\
                                       captured in destination qvo port but not in qvb port "
                        elif sndchkdstqvo == "norequestandreply":
                            print "check for flow table of dst host as request is captured in\
                                   dst vxlan port but not in dst qvo port"
		elif  sndchkdsttap == "noreply":
			     print "Check for iptables of dst vm"
 	elif sndchksrctap == "noreply" and sourcevm['host'] != dstvm['host']:
	    frstchkdsttap = response_check(dsttapreq, dsttaprep, dsttapreqcnt, srctaprepcnt)
	    if frstchkdsttap == "pass":
                frschksrcqvo = response_check(srcqvoreq, srcqvorep, srcqvoreqcnt, srcqvorepcnt)
    		if frschksrcqvo == "pass":
        	    frschksrcqvb = response_check(srcqvbreq, srcqvbrep, srcqvbreqcnt, srcqvbrepcnt)
        	    if frschksrcqvb == "pass":
                        print "check for mac table of linux bridge as reply reaches\
                               the source qvb port but not the tap port"
                    else:
                        print "check for veth connection in source node as reply reaches\
                               the source qvo port but not the source qvb port"
	        else:
                    frschkdstqvo = response_check(dstqvoreq, dstqvorep, dstqvoreqcnt, dstqvorepcnt)
                    if frschkdstqvo == "pass":
                        print "check for ovs flow table in dst node as reply reaches the \
                               destination qvo port but not the source qvo port"
                    else:
                        frschkdstqvb = response_check(dstqvbreq, dstqvbrep, dstqvbreqcnt, dstqvbrepcnt)
                        if frschkdstqvb == "pass":
                            print "check for veth connection in destination node as reply reaches the\
                                   destination qvb port but not the destination qvo port"
                        else:
                            print "check for mac  table of linux bridge in the destination node as\
                                   reply reaches the destination tap port but not the qvb port"
            else:
                sndchkdsttap, reqssrctap = request_check(dsttapreq, dsttaprep, dsttapreqcnt, dsttaprepcnt)
    		if sndchkdsttap == "norequestandreply":
        	    sndchksrcqvo == response_check(srcqvoreq, srcqvorep, srcqvoreqcnt, srcqvorepcnt)
		    if sndchksrcqvo == "norequestandreply":
			sndchksrcqvb = response_check(srcqvbreq, srcqvbrep, srcqvbreqcnt, srcqvbrepcnt)
			if sndchksrcqvb == "pass":
                            print "check for mac table of linux bridge as reply reaches\
                                   the source qvb port but not the tap port"
                        else:
			    print "check for veth connection in source node as reply reaches \
                            the source qvo port but not the source qvb port"
		    else:
			sndchkdstqvo = response_check(dstqvoreq, dstqvorep, dstqvoreqcnt, dstqvorepcnt)
			if sndchkdstqvo == "pass":
			    print "check for ovs flow table in dst node as reply reaches \
                                   the destination qvo port but not the source qvo port"
			else:
			    sndchkdstqvb = response_check(dstqvbreq, dstqvbrep, dstqvbreqcnt, dstqvbrepcnt)
			    if frschkdstqvb == "pass":
				print "check for veth connection in destination node as reply reaches \
                                       the destination qvb port but not the destination qvo port"
			    else:
				print "check for mac  table of linux bridge in the destination node as reply reaches the destination tap port but not the qvb port"
                elif sndchkdsttap == "noreply":
	            print "check for iptables of dst vm"
 
def tcpdumpcapture_validate_external(netnode_details, network_list, sourcevm, source_gatewayport, \
                                     srcvxlan, netvxlan, sourcevmports, router_gateway):
    print "Capturing tcpdump at tap port of source vm"
    srctapreq, srctaprep, srctapreqcnt, srctaprepcnt = requestandreplyparse(sourcevm['hostip']\
                                                       +sourcevmports[-1]+sourcevm['mac']+'.txt')
    print "Capturing tcpdump at qvb port of source vm"
    srcqvbreq, srcqvbrep, srcqvbreqcnt, srcqvbrepcnt = requestandreplyparse(sourcevm['hostip']+\
                                                       sourcevmports[1]+sourcevm['mac']+'.txt')
    print "Capturing tcpdump at qvo port of source vm"
    srcqvoreq, srcqvorep, srcqvoreqcnt, srcqvorepcnt = requestandreplyparse(sourcevm['hostip']+\
                                                        sourcevmports[2]+sourcevm['mac']+'.txt')
    print "Capturing tcpdump at vxlan port of source vm host"   
    srcvxlanreq, srcvxlanrep, srcvxlanreqcnt, srcvxlanrepcnt = requestandreplyparse(\
                                                               sourcevm['hostip']+srcvxlan[0]+sourcevm['mac']+'.txt')
    print "Capturing tcpdump at vxlan port of network node"
    netvxlanreq, netvxlanrep, netvxlanreqcnt, netvxlanrepcnt = requestandreplyparse\
(network_list[0]+netvxlan[0]+sourcevm['mac']+'.txt')
    print "Capturing tcpdump at router ports"
    netqr1req, netqr1rep, netqr1reqcnt, netqr1repcnt = requestandreplyparse(network_list[0]\
                                                 +source_gatewayport+sourcevm['mac']+'.txt')
    print ("Capturing tcpdump at router gateway")
    netqgreq,netqgrep,netqgreqcnt,netqgrepcnt=requestandreplyparse(network_list[0]+router_gateway['port_name']+sourcevm['mac']+'.txt')
    ext_port=external_physical_port(network_list[0])
    print ("Capturing tcpdump at physical port ")
    netphyreq,netphyrep,netphyreqcnt,netphyrepcnt=requestandreplyparse(network_list[0]+ext_port+sourcevm['floating_ip']+'.txt')
    #print netphyreq,netphyrep,netphyreqcnt,netphyrepcnt 
    frstchksrctap=response_check(srctapreq,srctaprep,srctapreqcnt,srctaprepcnt)
    if (frstchksrctap=="pass"):
        print ("ping test passed")
    else:   
        sndchksrctap,reqssrctap=request_check(srctapreq,srctaprep,srctapreqcnt,srctaprepcnt)
        if (sndchksrctap=="norequestandreply"):
            ports = port_validation_src(sourcevm['hostip'])
            print("There is no request and reply in the source tap port")
            if ports:
                print "Host  : ",ports[2]
                print "Port  : ",ports[0]['port_name'].strip('(').strip(')')
                print "Bridge: ",ports[1]
                print "Status: ","DOWN"
               #print("Port "+ports[0]['port_name']+" in "+ports[1]+" bridge in host "+ports[2]+" is down ") 
            else:   
                #print("No OVS ports are down on source host  checking physical connection")
                if getphysicalportstate(sourcevm['hostip']):
                    print "Host  : ",sourcevm['hostip']
                    print "Port  : ",getphysicalportstate(sourcevm['hostip'])[0]
                    print "Status: DOWN"
                elif getphysicalportstate(network_list[0]):
                    print "Host  : ",network_list[0]
                    print "Port  : ",getphysicalportstate(network_list[0])[0]
                    print "Status: DOWN"
                else:
                    print ("Checking iptables of source vm")
	elif (sndchksrctap=="noreply"):
	    frstchknetphy=response_check(netphyreq,netphyrep,netphyreqcnt,netphyrepcnt)
	    if (frstchknetphy=="pass"):
	        frstchknetvxlan==response_check(netvxlanreq,netvxlanrep,netvxlanreqcnt,netvxlanrepcnt)
	        if frstchknetvxlan=="pass":
		    frschksrcvxlan=response_check(srcvxlanreq,srcvxlanrep,srcvxlanreqcnt,srcvxlanrepcnt)
		    if frschksrcvxlan=="pass":
		        frschksrcqvo==response_check(srcqvoreq,srcqvorep,srcqvoreqcnt,srcqvorepcnt)
			if frschksrcqvo=="pass":
			    frschksrcqvb==response_check(srcqvbreq,srcqvbrep,srcqvbreqcnt,srcqvbrepcnt)
                            if frschksrcqvb=="pass":
                                print ("check for mac table of linux bridge as reply reaches the qvb port of the vm but not in the tap port of the vm")
                            else:
                                print ("check for veth connection in source node as reply reaches the qvo port of the vm but not the qvb port of the vm")
			else:
			    print ("check  for ovs flow table of source node as reply reaches the source host vxlan port bit not in the qvo port of the vm")
		    else:
		        print ("check Tunnel connection between network and source node as reply reaches the network node vxlan but not the source host vxlan") 
                else:
		    frstchknetqr1=response_check(netqr1req,netqr1rep,netqr1reqcnt,netqr1repcnt)
                    if frstchknetqr1=="fail":
                        frstchkqg=response_check(netqgreq,netqgrep,netqgreqcnt,netqgrepcnt)
           		if frstchkqg=="fail":
                   	    print("Checking iptables of network node as reply reaches the physical port but not in the external gateway port of the router")
			else:
		            print("Check the routing table in the router as reply reaches the external gateway of the router but not in the gateway of the vm")
		    else:
		        print("Check for the OVS flow table entries as reply reaches the gateway port but not in the vxlan port")
	    else:			
		sndchknetphy=request_check(netphyreq,netphyrep,netphyreqcnt,netphyrepcnt)
		if (sndchknetphy=="norequestandreply"):
		    print("Checking for the iptables of the network node")
	            sndchknetvxlan=request_check(netvxlanreq,netvxlanrep,netvxlanreqcnt,netvxlanrepcnt)
		    if (sndchknetvxlan=="norequestandreply"):
		        sndchksrcvxlan=request_check(srcvxlanreq,srcvxlanrep,srcvxlanreqcnt,srcvxlanrepcnt)
			if (sndchksrcvxlan=="norequestandreply"):
			    sndchksrcqvo,reqssrctap=request_check(srcqvoreq,srcqvorep,srcqvoreqcnt,srcqvorepcnt)
			    if (sndchksrcqvo=="norequestandreply"):
                                sndchksrcqvb,reqssrctap=request_check(srcqvbreq,srcqvbrep,srcqvbreqcnt,srcqvbrepcnt)
                                if (sndchksrcqvb=="norequestandreply"):
                                    print ("check for mac table of linux bridge as request comes out of source tap but not in source qvb port")
                                elif (sndchksrcqvb=="noreply"):
                                    print ("check for veth connection as request is captured in source qvb port but not in source qvo port")
                            elif (sndchksrcqvo=="noreply"):
                                print ("check for ovs flow table of source vm host as request is captured in source qvo port but not in the source vxlan port")
                        elif (sndchksrcvxlan=="noreply"):
                            print ("check for physical connection between source host and network node as request is captured in source host vxlan port but not in network node")
		    elif (sndchknetvxlan=="noreply"):	
		        sndchknetqr1=request_check(netqr1req,netqr1rep,netqr1reqcnt,netqr1repcnt)
		        if sndchknetqr1=="noreply":
			    sndchknetqg=request_check(netqgreq,netqgrep,netqgreqcnt,netqgrepcnt)
			    if sndchknetqg=="noreply":
				print ("Check for the iptables as request reaches the ezternal gateway but not in physical port")
                            else:
			        print ("Check the routing table as the request reaches the source gateway but not external gateway")
			else:
			    print("Check ovs flow entries as request reaches the network node vxlan port but not the source gateway")
		elif (sndchknetphy=="noreply"):
		    print ("check for the iptables in the network node") 
def tcpdumpcapture_validate_different_network(netnode_details,network_list,sourcevm,dstvm,source_gatewayport,dst_gatewayport,srcvxlan,dstvxlan,netvxlan,sourcevmports,dstvmports):
   srctapreq,srctaprep,srctapreqcnt,srctaprepcnt=requestandreplyparse(sourcevm['hostip']+sourcevmports[-1]+sourcevm['mac']+'.txt')
   print("Capturing tcpdump at qvb port of source vm")
   srcqvbreq,srcqvbrep,srcqvbreqcnt,srcqvbrepcnt=requestandreplyparse(sourcevm['hostip']+sourcevmports[1]+sourcevm['mac']+'.txt')
   print("Capturing tcpdump at qvo port of source vm")
   srcqvoreq,srcqvorep,srcqvoreqcnt,srcqvorepcnt=requestandreplyparse(sourcevm['hostip']+sourcevmports[2]+sourcevm['mac']+'.txt')
   print("Capturing tcpdump at vxlan port of source vm host")
   srcvxlanreq,srcvxlanrep,srcvxlanreqcnt,srcvxlanrepcnt=requestandreplyparse(sourcevm['hostip']+srcvxlan[0]+sourcevm['mac']+'.txt')
   print("Capturing tcpdump at tap port of destination vm")
   dsttapreq,dsttaprep,dsttapreqcnt,dsttaprepcnt=requestandreplyparse(dstvm['hostip']+dstvmports[-1]+dstvm['mac']+'.txt')
   print("Capturing tcpdump at qvb port of destination vm")
   dstqvbreq,dstqvbrep,dstqvbreqcnt,dstqvbrepcnt=requestandreplyparse(dstvm['hostip']+dstvmports[1]+dstvm['mac']+'.txt')
   print("Capturing tcpdump at qvo port of destination vm")
   dstqvoreq,dstqvorep,dstqvoreqcnt,dstqvorepcnt=requestandreplyparse(dstvm['hostip']+dstvmports[2]+dstvm['mac']+'.txt')
   print ("Capturing tcpdump at vxlan port of destination vm host")
   dstvxlanreq,dstvxlanrep,dstvxlanreqcnt,dstvxlanrepcnt=requestandreplyparse(dstvm['hostip']+dstvxlan[0]+dstvm['mac']+'.txt')
   #print (sourcevm['netid']!=dstvm['netid'])
   if sourcevm['netid']!=dstvm['netid']:
       print ("Capturing tcpdump at vxlan port of network node")
       netvxlanreq,netvxlanrep,netvxlanreqcnt,netvxlanrepcnt=requestandreplyparse(network_list[0]+netvxlan[0]+dstvm['mac']+'.txt')
       print ("Capturing tcpdump at router ports")
       netqr1req,netqr1rep,netqr1reqcnt,netqr1repcnt=requestandreplyparse(network_list[0]+source_gatewayport+dstvm['mac']+'.txt')
       netqr2req,netqr2rep,netqr2reqcnt,netqr2repcnt=requestandreplyparse(network_list[0]+dst_gatewayport+dstvm['mac']+'.txt')
   #print (srctapreq,srctaprep,srctapreqcnt,srctaprepcnt)
   #print (netvxlanreq,netvxlanrep,netvxlanreqcnt,netvxlanrepcnt)
   frstchksrctap=response_check(srctapreq,srctaprep,srctapreqcnt,srctaprepcnt)
   #print srctapreq,srctaprep,srctapreqcnt,srctaprepcnt,frstchksrctap
   if (frstchksrctap=="pass"):
       print ("ping test passed")
   else:
       #print srctapreq,srctaprep,srctapreqcnt,srctaprepcnt,request_check(srctapreq,srctaprep,srctapreqcnt,srctaprepcnt)
       sndchksrctap,reqssrctap=request_check(srctapreq,srctaprep,srctapreqcnt,srctaprepcnt)
       if (sndchksrctap=="norequestandreply"):
           ports = port_validation_src(sourcevm['hostip'])
           print("There is no request and reply in the source tap port")
           if ports:
	       print "Host  : ",ports[2]
	       print "Port  : ",ports[0]['port_name'].strip('(').strip(')')
	       print "Bridge: ",ports[1]
	       print "Status: ","DOWN"
	       #print("Port "+ports[0]['port_name']+" in "+ports[1]+" bridge in host "+ports[2]+" is down ")
           else:
               #print("No OVS ports are down on source host  checking physical connection")
	       if getphysicalportstate(sourcevm['hostip']):
	           print "Host  : ",sourcevm['hostip']
	           print "Port  : ",getphysicalportstate(sourcevm['hostip'])[0]
	           print "Status: DOWN"
               elif getphysicalportstate(network_list[0]):
	           print "Host  : ",network_list[0]
		   print "Port  : ",getphysicalportstate(network_list[0])[0]
		   print "Status: DOWN"
	       else:
		   print ("Checking iptables of source vm")

       elif (sndchksrctap=="noreply"):
           frstchkdsttap=response_check(dsttapreq,dsttaprep,dsttapreqcnt,dsttaprepcnt)
           if (frstchkdsttap=="pass"):
               frstchkdstvxlan=response_check(dstvxlanreq,dstvxlanrep,dstvxlanreqcnt,dstvxlanrepcnt)
               if frstchkdstvxlan=="pass":
                   frstchknetvxlan==response_check(netvxlanreq,netvxlanrep,netvxlanreqcnt,netvxlanrepcnt)
                   if frstchknetvxlan=="pass":
                       frstchknetqr2=response_check(netqr2req,netqr2rep,netqr2reqcnt,netqr2repcnt)
                       if frstchknetqr2=="pass":
                           frstchknetqr1=response_check(netqr1req,netqr1rep,netqr1reqcnt,netqr1repcnt)
                           if frstchknetqr1=="pass":
                               frschksrcvxlan=response_check(srcvxlanreq,srcvxlanrep,srcvxlanreqcnt,srcvxlanrepcnt)
                               if frschksrcvxlan =="pass":
                                   frschksrcqvo==response_check(srcqvoreq,srcqvorep,srcqvoreqcnt,srcqvorepcnt)
                                   if frschksrcqvo=="pass":                              
                                        frschksrcqvb==response_check(srcqvbreq,srcqvbrep,srcqvbreqcnt,srcqvbrepcnt)
                                        if frschksrcqvb=="pass":
                                            print ("check for mac table of linux bridge")
                                        else:
                                            print ("check for veth connection in source node")
                                   else:
                                       print ("check  for ovs flow table of source node")

                               else:
                                   print ("check Tunnel connection between network and source node")

                           else:
                                print ("check for routing table")
                       else:
                           print ("check for ovs flow table of network node" )
                   else:
                       print ("check Tunnel connection between network and the destination node")
               else:
                   frschkdstqvo=response_check(dstqvoreq,dstqvorep,dstqvoreqcnt,dstqvorepcnt)
                   if frschkdstqvo=="pass":
                       print ("check for ovs flow table in dst node")
                   else:
                       frschkdstqvb=response_check(dstqvbreq,dstqvbrep,dstqvbreqcnt,dstqvbrepcnt)
                       if frschkdstqvb=="pass":
                           print ("check for veth connection in destination node")
                       else:
                           print ("check for mac  table of linux bridge in the destination node")
           else:
               sndchkdsttap,reqssrctap=request_check(dsttapreq,dsttaprep,dsttapreqcnt,dsttaprepcnt)
               if (sndchkdsttap=="norequestandreply"):
                   print ("check for iptables of dst vm for both ingress and egress")
                   sndchkdstvxlan,reqssrctap=request_check(dstvxlanreq,dstvxlanrep,dstvxlanreqcnt,dstvxlanrepcnt)
                   if (sndchkdstvxlan=="norequestandreply"):
                       sndchknetvxlan,reqssrctap=request_check(netvxlanreq,netvxlanrep,netvxlanreqcnt,netvxlanrepcnt)
                       if (sndchknetvxlan=="norequestandreply"):
                           sndchknetqr2,reqssrctap=request_check(netqr2req,netqr2rep,netqr2reqcnt,netqr2repcnt)
                           if (sndchknetqr2=="norequestandreply"):
                               sndchknetqr1,reqssrctap=request_check(netqr1req,netqr1rep,netqr1reqcnt,netqr1repcnt)
                               if (sndchknetqr1=="norequestandreply"):
                                   sndchksrcvxlan,reqssrctap=request_check(srcvxlanreq,srcvxlanrep,srcqvbreqcnt,srcvxlanrepcnt)
                                   if (sndchksrcvxlan=="norequestandreply"):
                                       sndchksrcqvo,reqssrctap=request_check(srcqvoreq,srcqvorep,srcqvoreqcnt,srcqvorepcnt)
                                       if (sndchksrcqvo=="norequestandreply"):
                                           sndchksrcqvb,reqssrctap=request_check(srcqvbreq,srcqvbrep,srcqvbreqcnt,srcqvbrepcnt)
                                           if (sndchksrcqvb=="norequestandreply"):
                                               print ("check for mac table of linux bridge as request comes out of source tap but not in source qvb port")
                                           elif (sndchksrcqvb=="noreply"):
                                               print ("check for veth connection as request is captured in source qvb port but not in source qvo port")
                                       elif (sndchksrcqvo=="noreply"):
                                           print ("check for ovs flow table of source vm host as request is captured in source qvo port but not in the source vxlan port")
                                   elif (sndchksrcvxlan=="noreply"):
                                       print ("check for physical connection between source host and network node as request is captured in source host vxlan port but not in network node")
                               elif (sndchknetqr1=="noreply"):
                                   print("Request reaches src  gateway and it doesnt reach dst gateway")
                                   ports=port_validation_dst(network_list[0],netnode_details['routernamespace'],dstvm['ips'],dstvm['hostip'])
                                   if ports:
                                       # print("Port "+ports[0]['port_name']+" in "+ports[1]+" bridge in host "+ports[2]+" is down")
				       print "Host  : ",ports[2]
				       print "Port  : ",ports[0]['port_name'].strip(')').strip('(')
				       print "Bridge: ",ports[1] 
				       print "Status: ","DOWN"
                                   else:
                                       #print("No OVS ports in destination host are down check for physical connection")
				       if getphysicalportstate(dstvm['hostip']):
                	                   print "Host  : ",dstvm['hostip']
		                           print "Port  : ",getphysicalportstate(dstvm['hostip'])[0]
                   			   print "Status:  DOWN"	
				       else:
					   print "Check for Routing table " 
                           elif (sndchknetqr2=="noreply"):
                               print ("check for ovs flow table in network node as request is captured in dst gateway but not in network vxlan port ")
                       elif (sndchknetvxlan=="noreply"):
                           print ("check for physical connection between network node and dst node")
                   elif (sndchkdstvxlan=="noreply"):
                       sndchkdstqvo,reqssrctap=request_check(dstqvoreq,dstqvorep,dstqvoreqcnt,dstqvorepcnt)
                       if (sndchkdstqvo=="noreply"):
                           sndchkdstqvb,reqssrctap=request_check(dstqvbreq,dstqvbreqcnt,dstqvbrep,dstqvbrepcnt)
                           if (sndchkdstqvb=="noreply"):
                               print ("check for mac table of linux bridge in dst node")
                           elif (sndchkdstqvb=="norequestandreply"):
                               print("check for veth connection in dst node")
                       elif (sndchkdstqvo=="norequestandreply"):
                           print ("check for flow table of dst host as request is captured in dst vxlan port but not in dst qvo port")


               elif (sndchkdsttap=="noreply"):
                   print ("check for iptables of dst vm for egress")
 

#  closeping()
#tcpdumpcapture()
def main():
    type=raw_input("external connectivity or internal connectivity: ")
    controller_ip=raw_input("Enter the controller ip: ")
    source_vm_ip=raw_input("Enter the source VM ip: ")
    if type=="internal":
        destination_vm_ip=raw_input("Enter the Destination VM ip: ")
	print ("Collecting Node details and VM details please wait....") 
	compute_names,compute_list,network_list,sourcevm,dstvm,sourcevmports,dstvmports,srcvxlan,dstvxlan,subnet_list=datacollection(controller_ip,source_vm_ip,destination_vm_ip)
        e=initping(sourcevm['floating_ip'],dstvm['ips'])
	#print e
	print ("SSH to all nodes please wait...")
        tcpdumpcapturesource_destination(sourcevmports,dstvmports,sourcevm,dstvm,srcvxlan,dstvxlan)
	#print sourcevm
        if sourcevm['netid']!=dstvm['netid']:
	    netnode_details,source_gatewayport,dst_gatewayport,netvxlan=datacollection_networknode(network_list,sourcevm,dstvm,subnet_list)
	    tcpdumpcapture_networknode(netnode_details,network_list,sourcevm,dstvm,source_gatewayport,dst_gatewayport,netvxlan)
            tcpdumpcapture_validate_different_network(netnode_details,network_list,sourcevm,dstvm,source_gatewayport,dst_gatewayport,srcvxlan,dstvxlan,netvxlan,sourcevmports,dstvmports)
	else:
            tcpdumpcapture_validate_same_network(sourcevm,dstvm,srcvxlan,dstvxlan,sourcevmports,dstvmports)
    elif type=="external":
	print ("Collecting Node details and VM details please wait....")
	compute_names,compute_list,network_list,sourcevm,sourcevmports,srcvxlan,subnet_list=datacollecion_external(controller_ip,source_vm_ip)
        #print compute_names,compute_list,network_list,sourcevm,sourcevmports,srcvxlan,subnet_list
	e=initping(sourcevm['floating_ip'],'8.8.8.8')
	print ("SSH to all nodes please wait...")
        netnode_details,source_gatewayport,netvxlan,router_gateway=datacollection_networknode_external(network_list,sourcevm,subnet_list)
        #print netnode_details,source_gatewayport,netvxlan,router_gateway
        tcpdumpcapturesource_network_external(sourcevmports,sourcevm,srcvxlan,netnode_details,network_list,source_gatewayport,netvxlan,router_gateway)
 	#print  netnode_details,source_gatewayport,netvxlan,router_gateway,compute_names,compute_list,network_list,sourcevm,sourcevmports,srcvxlan,subnet_list
        tcpdumpcapture_validate_external(netnode_details,network_list,sourcevm,source_gatewayport,srcvxlan,netvxlan,sourcevmports,router_gateway)
if __name__=="__main__":
    main()
