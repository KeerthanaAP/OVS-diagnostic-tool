import paramiko
import re
import pprint
from fabric.api import  *
import netaddr
from threading import Thread
path ='/root/test/'

def datacollecion_external(controllerip,sourcevmip):
    compute_names,compute_list,network_list=get_nodes(controllerip,'cisco123')
    sourcevm=getvm_details(sourcevmip,controllerip)
    for x in range(len(compute_names)):
        if (sourcevm['host'] in compute_names[x]):
            sourcevm['hostip']=compute_list[x]
    sourcevm['ports'],srcvxlan=getserverports(sourcevm['portsid'],sourcevm['hostip'])
    sourcevmports=sourcevm['ports']
    sourcevmports.sort()
    subnet_list=get_subnets(controllerip)
    #print (subnet_list)
    sourcevm['netid']=get_networkid(sourcevm['ips'],subnet_list)
    #print  (sourcevm['netid'])
    return compute_names,compute_list,network_list,sourcevm,sourcevmports,srcvxlan,subnet_list

def datacollection_networknode_external(network_list,sourcevm,subnet_list):
    #print "***********************************"
    #print network_list,sourcevm,subnet_list
    netnode_details=getnetworknode_details(network_list[0])
    #print (netnode_details)
    for i in range(len(netnode_details['ports'])):
        netnode_details['ports'][i]['netid']=get_networkid(netnode_details['ports'][i]['ip'],subnet_list)
    for i in range(len(netnode_details['ports'])):
        if netnode_details['ports'][i]['netid']==sourcevm['netid']:
            source_gatewayport=netnode_details['ports'][i]['port_name']
       # print netnode_details['ports'][i]
	if 'qg' in netnode_details['ports'][i]['port_name']:
	    router_gateway=netnode_details['ports'][i]
    # print source_gatewayport,dst_gatewayport
    netvxlan=get_networknodevxlan(network_list[0])
    return netnode_details,source_gatewayport,netvxlan,router_gateway

def external_physical_port(ip):
    ssh=create_connection(ip)
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ip a | grep \"ens\|eth\" | grep state') 
    ipa=ssh_stdout.read().strip()
    #print ipa
    phyports=[]
    for line in ipa.split("\n"):
        l3=line.split()
        #print l3
        s=l3[1].strip(':')
        phyports.append(s)
    sh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ovs-vsctl list-ports br-ex') 
    br_ex_ports=ssh_stdout.read().strip()
    br_ex_ports=br_ex_ports.split("\n")
    #print br_ex_ports
    ssh.close()
    #print phyports
    for x in br_ex_ports:
        if x in phyports:
           #print x
            ext_port=x 
    return ext_port

def tcpdumpcapturesource_network_external(sourcevmports,sourcevm,srcvxlan,netnode_details,network_list,source_gatewayport,netvxlan,router_gateway):
    #print sourcevm['mac'],netnode_details['routernamespace'],netvxlan[0],router_gateway
    #print type(sourcevm['mac']),type(netnode_details['routernamespace']),type(netvxlan[0]),type(router_gateway)
    ext_port=external_physical_port(network_list[0])    
    threads1=[]
    t0 = Thread(target=tcpdump,args=(sourcevmports[-1],sourcevm['hostip'],sourcevm['mac']))
    t1=Thread(target=tcpdump,args=(sourcevmports[1],sourcevm['hostip'],sourcevm['mac']))
    #threads1.append(t1)
    t2=Thread(target=tcpdump,args=(sourcevmports[2],sourcevm['hostip'],sourcevm['mac']))
    #threads1.append(t2)
    t3=Thread(target=tcpdump,args=(srcvxlan[0],sourcevm['hostip'],sourcevm['mac']))
    #print sourcevm['mac']
    t4 = Thread(target=tcpdumpofnetworknode,args=(netvxlan[0],network_list[0],netnode_details['routernamespace'],sourcevm['mac']))
    t5 = Thread(target=tcpdumpofnetworknode,args=(source_gatewayport,network_list[0],netnode_details['routernamespace'],sourcevm['mac']))
    t6 = Thread(target=tcpdumpofnetworknode,args=(router_gateway['port_name'],network_list[0],netnode_details['routernamespace'],sourcevm['mac']))
    t7 = Thread(target=tcpdumpofnetworknode,args=(ext_port,network_list[0],netnode_details['routernamespace'],sourcevm['floating_ip']))
    for i in range(8):
        eval('t'+str(i)).start()
        threads1.append(eval('t'+str(i)))
    for s in threads1:
        s.join()

def datacollection_networknode(network_list,sourcevm,dstvm,subnet_list):
    netnode_details=getnetworknode_details(network_list[0])
    #print (netnode_details)
    for i in range(len(netnode_details['ports'])):
        netnode_details['ports'][i]['netid']=get_networkid(netnode_details['ports'][i]['ip'],subnet_list)
    for i in range(len(netnode_details['ports'])):
        if netnode_details['ports'][i]['netid']==sourcevm['netid']:
            source_gatewayport=netnode_details['ports'][i]['port_name']
	if netnode_details['ports'][i]['netid']==dstvm['netid']:
 	    dst_gatewayport=netnode_details['ports'][i]['port_name']	
    # print source_gatewayport,dst_gatewayport
    netvxlan=get_networknodevxlan(network_list[0])
    return netnode_details,source_gatewayport,dst_gatewayport,netvxlan

def tcpdumpcapture_networknode(netnode_details,network_list,sourcevm,dstvm,source_gatewayport,dst_gatewayport,netvxlan):
    threads2=[]
    tt0 = Thread(target=tcpdumpofnetworknode,args=(netvxlan[0],network_list[0],netnode_details['routernamespace'],dstvm['mac']))
    tt1 = Thread(target=tcpdumpofnetworknode,args=(source_gatewayport,network_list[0],netnode_details['routernamespace'],dstvm['mac']))
    tt2 = Thread(target=tcpdumpofnetworknode,args=(dst_gatewayport,network_list[0],netnode_details['routernamespace'],dstvm['mac']))
    for i in range(3):
        eval('tt'+str(i)).start()
        threads2.append(eval('tt'+str(i)))
    for s in threads2:
        s.join()

def tcpdumpcapturesource_destination(sourcevmports,dstvmports,sourcevm,dstvm,srcvxlan,dstvxlan):
    threads1=[]
    t0 = Thread(target=tcpdump,args=(sourcevmports[-1],sourcevm['hostip'],sourcevm['mac']))
    t1=Thread(target=tcpdump,args=(sourcevmports[1],sourcevm['hostip'],sourcevm['mac']))
    #threads1.append(t1)
    t2=Thread(target=tcpdump,args=(sourcevmports[2],sourcevm['hostip'],sourcevm['mac']))
    #threads1.append(t2)
    t3=Thread(target=tcpdump,args=(srcvxlan[0],sourcevm['hostip'],sourcevm['mac']))
    #threads1.append(t3)
    t4=Thread(target=tcpdump,args=(dstvmports[-1],dstvm['hostip'],dstvm['mac']))
    #threads1.append(t4)
    t5=Thread(target=tcpdump,args=(dstvmports[1],dstvm['hostip'],dstvm['mac']))
    #threads1.append(t5)
    t6=Thread(target=tcpdump,args=(dstvmports[2],dstvm['hostip'],dstvm['mac']))
    #threads1.append(t6)
    t7=Thread(target=tcpdump,args=(dstvxlan[0],dstvm['hostip'],dstvm['mac']))
    #threads1.append(t7)
    for i in range(8):
        eval('t'+str(i)).start()
        threads1.append(eval('t'+str(i)))
    for s in threads1:
        s.join()

def datacollection(controllerip,sourcevmip,dstvmip):
    compute_names,compute_list,network_list=get_nodes(controllerip,'cisco123')
    sourcevm=getvm_details(sourcevmip,controllerip)
    dstvm=getvm_details(dstvmip,controllerip)
    for x in range(len(compute_names)):
	if (sourcevm['host'] in compute_names[x]):
            sourcevm['hostip']=compute_list[x]
    for x in range(len(compute_names)):
	if (dstvm['host'] in compute_names[x]):
            dstvm['hostip']=compute_list[x]
    sourcevm['ports'],srcvxlan=getserverports(sourcevm['portsid'],sourcevm['hostip'])
    dstvm['ports'],dstvxlan=getserverports(dstvm['portsid'],dstvm['hostip'])
    sourcevmports=sourcevm['ports']
    sourcevmports.sort()
    dstvmports=dstvm['ports']
    dstvmports.sort()
    subnet_list=get_subnets(controllerip)
    #print (subnet_list)
    sourcevm['netid']=get_networkid(sourcevm['ips'],subnet_list)
    #print  (sourcevm['netid'])  
    dstvm['netid']=get_networkid(dstvm['ips'],subnet_list)
    return compute_names,compute_list,network_list,sourcevm,dstvm,sourcevmports,dstvmports,srcvxlan,dstvxlan,subnet_list

def getphysicalportstate(ip):
    ssh=create_connection(ip)
    ports=[]
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ip a | grep \"ens\|eth\" | grep state')
    ipa=ssh_stdout.read()
    for line in ipa.split("\n"):
        if 'DOWN' in line:
	   # print line
            l3=line.split()
            s=l3[1].strip(':')
            ports.append(s)
    return ports

def get_networknodevxlan(ip):
    ssh=create_connection(ip)
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ifconfig | grep vxlan')
    vxlanport=ssh_stdout.read()
    vxlan_port=[]
    for l in vxlanport.split('\n'):
         if l:
             port1=l.split(':')[0]
             vxlan_port.append(port1)
    return(vxlan_port)
    
def getnetworknode_details(ip):
    nenode={}
    ssh=create_connection(ip)
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ip netns')
    ipnetns=ssh_stdout.read()
    for line in ipnetns.split("\n"):
 	if 'router' in line:
	    nenode['routernamespace']=line.strip()
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ip netns exec '+nenode['routernamespace']+' ifconfig')
    routerifconfig=ssh_stdout.read()
    routerifconfig=routerifconfig.strip()
    route_flag = 0
    network_port =[]
   # print routerifconfig
    for line in routerifconfig.split("\n"):
        line=line.strip()
	#print line
	#print re.search(r'(qg\-\w+)|(qr\-\w+)',line)
        if re.search(r'(qg\-\w+)|(qr\-\w+)',line):            
            router_name = line.split(":")[0]
            n={}
	    n['port_name']=router_name
	    #print (router_name)
            route_flag = 1
        if "inet " in line and route_flag ==1:            
            n['ip']= line.split(" ")[1]
	    network_port.append(n)
    nenode['ports']=network_port
    #print(network_port,nenode['ports'])
    return nenode

def get_networkid(ip,net):
    for x in range(len(net)):
        ip1 = netaddr.IPAddress(ip).value
        network = netaddr.IPNetwork(net[x]['cidr'])
         #print ip1,network
        if ip1 >= network.first and ip1 <= network.last:
            return net[x]['id']
        else:
            continue
    return 1

def get_subnets(hostip):
    ssh=create_connection(hostip)
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('openstack subnet list --os-auth-url http://10.11.0.42:5000/v3 --os-username admin --os-password cisco123 --os-user-domain-name Default --os-identity-api-version 3 --os-project-name admin --os-project-domain-name Default')
    subnet_out=ssh_stdout.read()
    subnets=[]
    for l in subnet_out.split("\n"):
        l1=l.split('|')
	#print (l1)
	subnet_lists={}
	if (len(l1)==6 and l1[1].strip()!='ID'):
            subnet_lists['cidr']=l1[4].strip()
	    subnet_lists['id']=l1[1].strip()	
            subnets.append(subnet_lists)
    return subnets

def initping(sourceip,dstip):
    #ssh1=create_connection(host_ip=sourceip,username="cirros",password="cubswin:)")
    #ssh1_stdin,ssh1_stdout,ssh1_stderr =ssh1.exec_command(' ping 172.16.2.6 -c 100000 &')
    ssh1=execute(check_ping, 'cirros', 'cubswin:)', hosts=[sourceip],dst=dstip)

def check_ping(username, password, dst):
    try:
        with settings(user= username, password=password, warn_only = True):
            sudo('ping '+dst+' -c 100 > out &',pty=False, shell=False)
    except Exception as e:
    	return e
	
global server
def getserverports(portsstart,hostip):
    ssh=create_connection(hostip)
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ifconfig | grep '+portsstart)
    vmports=ssh_stdout.read()
    ports=[]
    for line in vmports.split('\n'):
	if line:
	    port1=line.split(':')[0]
	    ports.append(port1)
    #print (ports)	
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ifconfig | grep vxlan')
    vxlanport=ssh_stdout.read()
    vxlan_port=[]
    for l in vxlanport.split('\n'):
	if l:
	    port1=l.split(':')[0]
            vxlan_port.append(port1)
    return ports,vxlan_port

def getvm_details(ip1,hostip):
    server={}
    ssh=create_connection(hostip)
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('source /root/keystonerc_admin ; openstack server list')
    server_list= hypervisor_list=ssh_stdout.read()
    id_pattern = r'^\s*\|\s*\S+\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*\S+=%s,*\s*\S*\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*$' % ip1
    server_name_status = re.findall(id_pattern,server_list,re.MULTILINE)
    id_pattern = r'^\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*\S+=%s,*\s*(\S*)\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*$' % ip1
    server_floatingip = re.findall(id_pattern,server_list,re.MULTILINE)
    #print ( server_list,server_name_status)
    server['ips']=ip1
    server['floating_ip']=server_floatingip[0]
    server['name']=server_name_status[0][0]
    server['status']=server_name_status[0][1]
    #print (server_name_status[0][1]=='ACTIVE') 
    if (server_name_status[0][1]=='ACTIVE'):
        cmd='source /root/keystonerc_admin ; nova interface-list '+server_name_status[0][0]
	#print cmd
	ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command(cmd)
	server_interface_details=ssh_stdout.read()
	#print (server_interface_details) 
	id_pattern = r'^\s*\|\s*\S+\s*\|\s*(\S+)\s*\|\s*\S+\s*\|\s*%s\s*\|\s*\S+\s*\|\s*$' % ip1
	server_portid=re.findall(id_pattern,server_interface_details,re.MULTILINE)
	id_pattern = r'^\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*%s\s*\|\s*(\S+)\s*\|\s*$' % ip1
        mac=re.findall(id_pattern,server_interface_details,re.MULTILINE)
        serverportsstart=server_portid[0][:11]
	ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('source /root/keystonerc_admin ; openstack server show '+server_name_status[0][0])
	server_show=ssh_stdout.read()
	id_pattern = r'^\s*\|\s*%s\s*\|\s*(\S+)\s*\|\s*$' % 'OS-EXT-SRV-ATTR:host'
	server_host=re.findall(id_pattern,server_show,re.MULTILINE)
	server['port']=server_portid[0]
	server['mac']=mac[0]
	server['portsid']=serverportsstart
	server['host']=server_host[0]
    return server

def down_port_check(out):    
    prev_line = ""
    down_port_count = 0
    port_dict = {}
    for line in out.split("\n"):
        
        if "PORT_DOWN" in line:
            if re.search(r'(\d+)(\(\w+\-\w+\))', prev_line, re.IGNORECASE):
                dict = re.search(r'(\d+)(\(\w+\-\w+\))', prev_line, re.IGNORECASE)
                port_name= dict.group(2)
                port_dict['port_name']= port_name
                down_port_count += 1
        else:
            pass
        prev_line = line
    #if down_port_count == 0:
    #   print("No ports are down")
    #pprint.pprint(port_dict)
    if port_dict:
	return port_dict


def arp_table_entries(result,dst_ip):
    status = 1
    for line in result.split("\n"):
        if dst_ip in line:
            if "incomplete" in line:
                status = 0
        else:
            pass
    return status

def port_validation_dst(netip,rns,dstip,dsthostip):
    ports=[]
    ssh=create_connection(netip)
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ip netns exec '+rns+' arp')
    arp_output=str(ssh_stdout.read())
    status = arp_table_entries(arp_output, dstip)
    ssh.close()
    #print(status)
    if status == 0:
        ssh=create_connection(dsthostip)
	ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ovs-ofctl show br-int')
	output = str(ssh_stdout.read())
        s=down_port_check(output)
        if s!=None:
	    ports.append(s)
	    ports.append('br-int')
            ports.append(dsthostip)
	ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ovs-ofctl show br-tun')
	output = str(ssh_stdout.read())
        s=down_port_check(output)
        if s!=None:
            ports.append(s)
            ports.append('br-tun')
	    ports.append(dsthostip)		
	    #`ports.append(down_port_check(output))
	return ports
    

def port_validation_src(src_hostip):
    ports=[]
    ssh=create_connection(src_hostip)
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ovs-ofctl show br-int')
    output = str(ssh_stdout.read())
    s=down_port_check(output)
    if s!=None:
        ports.append(s)
        ports.append('br-int')
        ports.append(src_hostip)
    #ports.append(down_port_check(output))
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('ovs-ofctl show br-tun')
    output = str(ssh_stdout.read())
    s=down_port_check(output)
    if s!=None:
	ports.append(s)
	ports.append('br-tun')
        ports.append(src_hostip)
    #print ports
    return ports
    

def requestandreplyparse(filename):
    global request
    global reply
    filename=path+filename
    request={}
    reply={}
    reqf=0
    repf=0
    reqcount=1
    repcount=1
    alreqflag=0
    for line in open(filename).readlines():
        #print (line.split(','))
        alreqflag=0
        alrepflag=0
        if 'ICMP echo request' in line and reqf==0:
            n=("req"+str(reqcount))
            request[n]={}
            request[n]['request_srcmac']=line.split(',')[0].split(' ')[1]
            request[n]['request_dstmac']=line.split(',')[0].split(' ')[3]
            request[n]['request_srcip']=line.split(',')[2].split(' ')[3]
            request[n]['request_dstip']=line.split(',')[2].split(' ')[5].strip(':')
            #print (request)
            reqf=1;
            reqcount=reqcount+1
           
        elif 'ICMP echo request' in line and reqf==1:
            for i in range(1,reqcount):
                n=("req"+str(i))
                #print ("request[n]['request_srcmac']",request[n]['request_srcmac'])
                if request[n]['request_srcmac'] == line.split(',')[0].split(' ')[1]:
                    alreqflag=1;
                    break;
            if alreqflag==1:
                continue;
            else:
                n=("req"+str(reqcount))
                request[n]={}
                request[n]['request_srcmac']=line.split(',')[0].split(' ')[1]
                request[n]['request_dstmac']=line.split(',')[0].split(' ')[3]
                request[n]['request_srcip']=line.split(',')[2].split(' ')[3]
                request[n]['request_dstip']=line.split(',')[2].split(' ')[5].strip(':')
                reqcount=reqcount+1
        
        if 'ICMP echo reply' in line and repf==0:
            n=("rep"+str(repcount))
            reply[n]={}
            reply[n]['reply_srcmac']=line.split(',')[0].split(' ')[1]
            reply[n]['reply_dstmac']=line.split(',')[0].split(' ')[3]
            reply[n]['reply_srcip']=line.split(',')[2].split(' ')[3]
            reply[n]['reply_dstip']=line.split(',')[2].split(' ')[5].strip(':')
            repf=1;
            repcount=repcount+1
        elif 'ICMP echo reply' in line and repf==1:
            for i in range(1,repcount):
                n=("rep"+str(i))
                #print ("request[n]['request_srcmac']",request[n]['request_srcmac'])
                if reply[n]['reply_srcmac'] == line.split(',')[0].split(' ')[1]:
                    alrepflag=1;
                    break;
            if alrepflag==1:
                continue;
            else:
                n=("rep"+str(repcount))
                reply[n]={}
                reply[n]['reply_srcmac']=line.split(',')[0].split(' ')[1]
                reply[n]['reply_dstmac']=line.split(',')[0].split(' ')[3]
                reply[n]['reply_srcip']=line.split(',')[2].split(' ')[3]
                reply[n]['reply_dstip']=line.split(',')[2].split(' ')[5].strip(':')
                repcount=repcount+1
        #print (repcount,reqcount)
    return (request,reply,reqcount,repcount)

def create_connection(host_ip,username="root", password="cisco123"):
    sshcon = paramiko.SSHClient()
    sshcon.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
            sshcon.connect(host_ip.strip("\""),
                           username=username.strip("\""),
                           password=password.strip("\""),
                           timeout=5)
    except paramiko.ssh_exception.AuthenticationException as exp:
        return None
    except socket.error as exp:
        return None
    return sshcon

def get_nodes(ip,password):
    ssh=create_connection(host_ip=ip,password=password)
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('openstack hypervisor list --os-auth-url http://10.11.0.42:5000/v3 --os-username admin --os-password cisco123 --os-user-domain-name Default --os-identity-api-version 3 --os-project-name admin --os-project-domain-name Default')
    hypervisor_list=ssh_stdout.read()
    id_pattern = r'^\s*\|\s*\d+\s*\|\s*\S+\s*\|\s*%s\s*\|\s*(\S+)\s*\|\s*\S+\s*\|\s*$' % 'QEMU'
    ids = re.findall(id_pattern, hypervisor_list, re.MULTILINE)
    compute_list=ids
    id_pattern = r'^\s*\|\s*\d+\s*\|\s*(\S+)\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*%s\s*\|\s*$' % 'up'
    names = re.findall(id_pattern,hypervisor_list,re.MULTILINE)
    computename_list=names
    ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('openstack network agent list --os-auth-url http://10.11.0.42:5000/v3 --os-username admin --os-password cisco123 --os-user-domain-name Default --os-identity-api-version 3 --os-project-name admin --os-project-domain-name Default')
    networkagent_list=ssh_stdout.read()
    id_pattern = r'^\s*\|\s*\S+\s*\|\s*%s\s*\|\s*(\S+)\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*$' % 'Metadata agent'
    networkname_list=re.findall(id_pattern,networkagent_list,re.MULTILINE)
    #print (networkname_list)
    network_list=[]
    for i in range(len(networkname_list)):
        ssh_stdin,ssh_stdout,ssh_stderr = ssh.exec_command('resolveip '+networkname_list[i])
	nn=ssh_stdout.read().split()
	#print (nn)
 	network_list.append(nn[-1])
        #print (network_list)
    #print (compute_list,network_list)
    return (computename_list,compute_list,network_list)                         
    ssh.close()

def tcpdump (interface,ip,grepid):
    ssh=create_connection(ip)
    cmd='timeout 10 tcpdump -i '+interface+' -n -e icmp | grep '+grepid
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('timeout 10 tcpdump -i '+interface+' -n -e icmp | grep '+grepid)
    tap_pcap=ssh_stdout.read()
    #print tap_pcap,cmd
    filename=path+ip+interface+grepid+'.txt'
    with open (filename,'wb') as ff:
        ff.write(tap_pcap)
    #return tap_pcap
    #return requestandreplyparse(filename)
    ssh.close()
	
def tcpdumpofnetworknode(interface,ip,rns,dstmac):
    ssh=create_connection(ip)
    #print ('qr' in interface or 'qg' in interface)
    if 'qr' in interface  or  'qg' in interface:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('timeout 10 ip netns exec '+rns+' tcpdump -i '+interface+' -n -e icmp')
    else :
	#print dstmac
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('timeout 10 tcpdump -i '+interface+' -n -e icmp | grep '+dstmac)
    tap_pcap=ssh_stdout.read()
    filename=path+ip+interface+dstmac+'.txt'
    #print dstmac,filename
    with open (filename,'wb') as ff:
	ff.write(tap_pcap)
    #return requestandreplyparse(filename)
    ssh.close()
def response_check(rq,rep,rqcount,repcount):
    passed=1
    for i in range(1,rqcount):
        n=("req"+str(i))
        for j in range(1,repcount):
            nrp=("rep"+str(j))
	    #print rq[n]['request_srcmac']==rep[nrp]['reply_dstmac'],rq[n]['request_dstmac']==rep[nrp]['reply_srcmac']
	    #print rq[n]['request_dstip']==rep[nrp]['reply_srcip'],rq[n]['request_srcip']==rep[nrp]['reply_dstip']
            if (rq[n]['request_srcmac']==rep[nrp]['reply_dstmac']) and (rq[n]['request_dstmac']==rep[nrp]['reply_srcmac']) and (rq[n]['request_dstip']==rep[nrp]['reply_srcip']) and (rq[n]['request_srcip']==rep[nrp]['reply_dstip']):
                passed=passed+1
                break;
    #print (passed,rqcount)
    if passed==rqcount and rqcount!=1:
        return ("pass")
    else:
        return ("fail")
def request_check(rq,rep,rqcount,repcount):
    norep=[]
    #print (rq)
    #print (rep)
    #print (rqcount,repcount)
    if rqcount==1 and repcount==1:
        return ("norequestandreply",norep)
    elif (rqcount>repcount):
        if repcount==1:
            norep.append(rq['req1'])
            return ("noreply",norep)
        else:
            
            for i in range(1,rqcount):
                passed=0
                n=("req"+str(i))
                for j in range(1,repcount):
                    nrp=("rep"+str(j))
                    if (rq[n]['request_srcmac']==rep[nrp]['reply_dstmac']) and (rq[n]['request_dstmac']==rep[nrp]['reply_srcmac']) and (rq[n]['request_dstip']==rep[nrp]['reply_srcip']) and (rq[n]['request_srcip']==rep[nrp]['reply_dstip']):
                        passed=1
                        break;
                if passed==0:
                    norep.append(rq[n])
            return ("noreply",norep)
