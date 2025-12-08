"""
Service Discovery Modules
Phát hiện các microservices từ Kubernetes, Docker, Consul
"""

from typing import List, Dict, Optional
import requests
import json
import subprocess


class ServiceDiscoveryBase:
    """Base class cho service discovery"""
    
    def discover_services(self) -> List[Dict[str, str]]:
        """Discover services - override trong subclass"""
        raise NotImplementedError


class KubernetesDiscovery(ServiceDiscoveryBase):
    """Discover services từ Kubernetes API"""
    
    def __init__(self, kubeconfig_path: Optional[str] = None, api_server: Optional[str] = None, token: Optional[str] = None):
        self.kubeconfig_path = kubeconfig_path
        self.api_server = api_server or "https://kubernetes.default.svc"
        self.token = token
    
    def discover_services(self) -> List[Dict[str, str]]:
        """Discover K8s services"""
        services = []
        
        try:
            # Try to use kubectl if available
            if self.kubeconfig_path:
                result = subprocess.run(
                    ['kubectl', '--kubeconfig', self.kubeconfig_path, 'get', 'services', '-A', '-o', 'json'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    for item in data.get('items', []):
                        metadata = item.get('metadata', {})
                        spec = item.get('spec', {})
                        
                        service_name = metadata.get('name')
                        namespace = metadata.get('namespace')
                        cluster_ip = spec.get('clusterIP')
                        ports = spec.get('ports', [])
                        
                        for port in ports:
                            port_num = port.get('port')
                            protocol = port.get('protocol', 'TCP')
                            
                            services.append({
                                'name': service_name,
                                'namespace': namespace,
                                'url': f'http://{service_name}.{namespace}.svc.cluster.local:{port_num}',
                                'ip': cluster_ip,
                                'port': port_num,
                                'protocol': protocol,
                                'source': 'kubernetes'
                            })
            
            # Try API access if token provided
            elif self.token:
                headers = {'Authorization': f'Bearer {self.token}'}
                response = requests.get(
                    f'{self.api_server}/api/v1/services',
                    headers=headers,
                    verify=False,
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get('items', []):
                        metadata = item.get('metadata', {})
                        spec = item.get('spec', {})
                        
                        services.append({
                            'name': metadata.get('name'),
                            'namespace': metadata.get('namespace'),
                            'url': f"http://{spec.get('clusterIP')}",
                            'source': 'kubernetes_api'
                        })
        
        except Exception as e:
            print(f"[!] K8s discovery error: {e}")
        
        return services


class ConsulDiscovery(ServiceDiscoveryBase):
    """Discover services từ Consul"""
    
    def __init__(self, consul_address: str = "http://127.0.0.1:8500"):
        self.consul_address = consul_address.rstrip('/')
    
    def discover_services(self) -> List[Dict[str, str]]:
        """Discover Consul services"""
        services = []
        
        try:
            # Get catalog
            response = requests.get(
                f'{self.consul_address}/v1/catalog/services',
                timeout=10
            )
            
            if response.status_code == 200:
                service_names = response.json()
                
                # Get details for each service
                for service_name in service_names.keys():
                    detail_response = requests.get(
                        f'{self.consul_address}/v1/catalog/service/{service_name}',
                        timeout=10
                    )
                    
                    if detail_response.status_code == 200:
                        service_instances = detail_response.json()
                        
                        for instance in service_instances:
                            address = instance.get('ServiceAddress') or instance.get('Address')
                            port = instance.get('ServicePort')
                            
                            services.append({
                                'name': service_name,
                                'url': f'http://{address}:{port}',
                                'ip': address,
                                'port': port,
                                'source': 'consul'
                            })
        
        except Exception as e:
            print(f"[!] Consul discovery error: {e}")
        
        return services


class DockerDiscovery(ServiceDiscoveryBase):
    """Discover services từ Docker"""
    
    def __init__(self, docker_host: str = "unix:///var/run/docker.sock"):
        self.docker_host = docker_host
    
    def discover_services(self) -> List[Dict[str, str]]:
        """Discover Docker containers"""
        services = []
        
        try:
            # Use docker CLI
            result = subprocess.run(
                ['docker', 'ps', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        container = json.loads(line)
                        
                        # Extract ports
                        ports_str = container.get('Ports', '')
                        exposed_ports = []
                        
                        if ports_str:
                            # Parse ports like "0.0.0.0:8080->80/tcp"
                            for port_mapping in ports_str.split(','):
                                if '->' in port_mapping:
                                    host_part = port_mapping.split('->')[0]
                                    if ':' in host_part:
                                        port = host_part.split(':')[-1].strip()
                                        exposed_ports.append(port)
                        
                        container_name = container.get('Names', 'unknown')
                        
                        for port in exposed_ports:
                            services.append({
                                'name': container_name,
                                'url': f'http://127.0.0.1:{port}',
                                'port': port,
                                'container_id': container.get('ID'),
                                'image': container.get('Image'),
                                'source': 'docker'
                            })
        
        except Exception as e:
            print(f"[!] Docker discovery error: {e}")
        
        return services


class ServiceDiscoveryManager:
    """Manager tổng hợp tất cả discovery sources"""
    
    def __init__(self):
        self.discoverers = {}
    
    def add_kubernetes(self, kubeconfig_path: Optional[str] = None, api_server: Optional[str] = None, token: Optional[str] = None):
        """Add Kubernetes discovery"""
        self.discoverers['kubernetes'] = KubernetesDiscovery(kubeconfig_path, api_server, token)
    
    def add_consul(self, consul_address: str = "http://127.0.0.1:8500"):
        """Add Consul discovery"""
        self.discoverers['consul'] = ConsulDiscovery(consul_address)
    
    def add_docker(self, docker_host: str = "unix:///var/run/docker.sock"):
        """Add Docker discovery"""
        self.discoverers['docker'] = DockerDiscovery(docker_host)
    
    def discover_all(self) -> Dict[str, List[Dict]]:
        """Discover từ tất cả sources"""
        results = {}
        
        for source_name, discoverer in self.discoverers.items():
            print(f"[*] Discovering services from {source_name}...")
            try:
                services = discoverer.discover_services()
                results[source_name] = services
                print(f"    ✓ Found {len(services)} services from {source_name}")
            except Exception as e:
                print(f"    ✗ Error discovering from {source_name}: {e}")
                results[source_name] = []
        
        return results
    
    def get_all_services(self) -> List[Dict]:
        """Get flat list of all services"""
        all_services = []
        results = self.discover_all()
        
        for source_services in results.values():
            all_services.extend(source_services)
        
        return all_services


def create_service_discovery_manager(
    enable_kubernetes: bool = False,
    enable_consul: bool = False,
    enable_docker: bool = False,
    kubeconfig_path: Optional[str] = None,
    consul_address: Optional[str] = None,
    docker_host: Optional[str] = None
) -> ServiceDiscoveryManager:
    """Factory function để tạo ServiceDiscoveryManager"""
    
    manager = ServiceDiscoveryManager()
    
    if enable_kubernetes:
        manager.add_kubernetes(kubeconfig_path)
    
    if enable_consul:
        manager.add_consul(consul_address or "http://127.0.0.1:8500")
    
    if enable_docker:
        manager.add_docker(docker_host or "unix:///var/run/docker.sock")
    
    return manager
