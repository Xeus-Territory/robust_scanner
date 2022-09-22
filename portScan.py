from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from socket import getservbyport
from socket import gethostbyname
from concurrent.futures import ThreadPoolExecutor
from terminaltables import SingleTable

class PortScan:
    def __init__(self, host, port, protocolname):
        self.host = host
        self.ports = port
        self.protocolname = protocolname
        
    def find_service_name(self, port):
        try:
            if self.protocolname == 'both':
                if getservbyport(port, 'tcp') is not None:
                    return 'tcp',getservbyport(port, 'tcp')
                if getservbyport(port, 'udp') is not None:
                    return 'udp',getservbyport(port, 'udp')
            if self.protocolname == 'tcp':
                if getservbyport(port, 'tcp') is None:
                    return 'Service serve for other protocol'
                if getservbyport(port, 'tcp') is not None:
                    return 'tcp',getservbyport(port, 'tcp')
            if self.protocolname == 'udp':
                if getservbyport(port, 'udp') is None:
                    return 'Service serve for other protocol'
                if getservbyport(port, 'udp') is not None:
                    return 'udp',getservbyport(port, 'udp')
        except:
            return 'tcp', '---'
                
            
    
    def test_port_number_forrange(self, host, port):
        # Create a socket and set timeout if port doesn't exist and otherwise
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.settimeout(3)
            # So try to connect
            try:
                sock.connect((host, port))
                # Check if it succeeded return True 
                return True
            except:
                # Check if it failed return False
                return False
            
    def test_port_number_particular(self, host, port):
        try:
            sock = socket(AF_INET, SOCK_STREAM) 
            sock.settimeout(3)
            cnn = sock.connect_ex((host, port))
            if cnn == 0:
                return True
            sock.close()
        except:
            return False
            
    def port_scan(self):
        print(f'Host: {self.host} via IP address: {gethostbyname(self.host)}')
        port_report = []
        port_report.append(['PORT', 'STATE', 'NAME SERVICE'])
        # print('\t\tPORT\t\tSTATE\t\tNAME SERVICE\t\t')
        for port in self.ports:
            if self.test_port_number_particular(self.host, port):
                try:
                    pro_name, ser_name = self.find_service_name(port)
                    port_report.append([str(port) + '/' + pro_name, 'open', ser_name])
                    # print(f'\t\t{port}/{pro_name}\t\topen\t\t{ser_name}')
                except OSError:
                    port_report.append([str(port) + '/' + pro_name, 'close', ser_name])
                    # print(f'\t\t{port}/{pro_name}\t\tclose\t\t{ser_name}')
        port_report_table = SingleTable(port_report)
        port_report_table.title = 'Find Port...'
        print(port_report_table.table)            
        
                
                
    
    def port_scan_forrange(self):
        # Create thread pool for Up speed scan for tool 
        with ThreadPoolExecutor(len(self.ports)) as executor:
            # Do test port number with host on pool of thread
            results = executor.map(self.test_port_number_forrange, [self.host]*len(self.ports), self.ports)
            print(f'Host: {self.host} via IP address: [{gethostbyname(self.host)}]')
            port_report = []
            port_report.append(['PORT', 'STATE', 'NAME SERVICE'])
            # Report results
            # print('\t\tPORT\t\tSTATE\t\tNAME SERVICE\t\t')
            for port, is_open in zip(self.ports, results):
                if is_open:
                    pro_name, ser_name = self.find_service_name(port)
                    port_report.append([str(port) + '/' + pro_name, 'open', ser_name])
                    # print(f'\t\t{port}/{pro_name}\t\topen\t\t{ser_name}')
            
            port_report_table = SingleTable(port_report)
            port_report_table.title = 'Find Port...'
            print(port_report_table.table) 
            

                        
            
                

            
        

