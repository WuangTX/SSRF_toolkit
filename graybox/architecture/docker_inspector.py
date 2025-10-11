"""
Docker Inspector - Gray Box Module
Phân tích Docker environment để tìm network topology
"""

import docker
import json
import subprocess
from typing import List, Dict, Optional

class DockerInspector:
    """Inspector cho Docker environments"""
    
    def __init__(self, docker_host: Optional[str] = None):
        """
        Args:
            docker_host: Docker socket path (default: unix:///var/run/docker.sock)
        """
        try:
            if docker_host:
                self.client = docker.DockerClient(base_url=docker_host)
            else:
                self.client = docker.from_env()
            
            self.is_available = True
        except Exception as e:
            print(f"[!] Docker not available: {e}")
            self.is_available = False
            self.client = None
    
    def get_networks(self) -> List[Dict]:
        """Lấy tất cả Docker networks"""
        if not self.is_available:
            return []
        
        networks = []
        
        for network in self.client.networks.list():
            network_info = {
                'id': network.id[:12],
                'name': network.name,
                'driver': network.attrs.get('Driver'),
                'scope': network.attrs.get('Scope'),
                'subnet': None,
                'gateway': None,
                'containers': []
            }
            
            # Get IPAM config
            ipam = network.attrs.get('IPAM', {})
            config = ipam.get('Config', [])
            if config:
                network_info['subnet'] = config[0].get('Subnet')
                network_info['gateway'] = config[0].get('Gateway')
            
            # Get containers in network
            containers = network.attrs.get('Containers', {})
            for container_id, container_data in containers.items():
                network_info['containers'].append({
                    'id': container_id[:12],
                    'name': container_data.get('Name'),
                    'ipv4': container_data.get('IPv4Address', '').split('/')[0],
                    'ipv6': container_data.get('IPv6Address', '').split('/')[0] if container_data.get('IPv6Address') else None
                })
            
            networks.append(network_info)
        
        return networks
    
    def get_containers(self) -> List[Dict]:
        """Lấy tất cả running containers"""
        if not self.is_available:
            return []
        
        containers = []
        
        for container in self.client.containers.list():
            container_info = {
                'id': container.id[:12],
                'name': container.name,
                'image': container.image.tags[0] if container.image.tags else container.image.short_id,
                'status': container.status,
                'ports': self._parse_ports(container.ports),
                'networks': {},
                'environment': container.attrs.get('Config', {}).get('Env', [])
            }
            
            # Get network info
            network_settings = container.attrs.get('NetworkSettings', {})
            networks = network_settings.get('Networks', {})
            
            for network_name, network_data in networks.items():
                container_info['networks'][network_name] = {
                    'ip_address': network_data.get('IPAddress'),
                    'gateway': network_data.get('Gateway'),
                    'mac_address': network_data.get('MacAddress')
                }
            
            containers.append(container_info)
        
        return containers
    
    def _parse_ports(self, ports: Dict) -> List[Dict]:
        """Parse port mappings"""
        parsed_ports = []
        
        for container_port, host_bindings in ports.items():
            if host_bindings:
                for binding in host_bindings:
                    parsed_ports.append({
                        'container_port': container_port,
                        'host_ip': binding.get('HostIp', '0.0.0.0'),
                        'host_port': binding.get('HostPort')
                    })
        
        return parsed_ports
    
    def find_ssrf_targets(self) -> List[Dict]:
        """
        Tìm các targets tiềm năng cho SSRF attacks
        Dựa trên network topology
        """
        targets = []
        
        containers = self.get_containers()
        networks = self.get_networks()
        
        # Tìm containers có exposed ports (potential entry points)
        entry_points = [c for c in containers if c['ports']]
        
        # Tìm internal services (no exposed ports)
        internal_services = [c for c in containers if not c['ports']]
        
        # Tạo attack matrix
        for entry in entry_points:
            for internal in internal_services:
                # Check if they're in same network
                entry_networks = set(entry['networks'].keys())
                internal_networks = set(internal['networks'].keys())
                
                common_networks = entry_networks & internal_networks
                
                if common_networks:
                    # They can communicate
                    for network_name in common_networks:
                        internal_ip = internal['networks'][network_name]['ip_address']
                        
                        targets.append({
                            'entry_point': {
                                'name': entry['name'],
                                'exposed_ports': entry['ports']
                            },
                            'target': {
                                'name': internal['name'],
                                'ip': internal_ip,
                                'network': network_name
                            },
                            'attack_scenario': f"SSRF from {entry['name']} to {internal['name']} ({internal_ip})"
                        })
        
        return targets
    
    def generate_network_diagram(self) -> str:
        """Generate text-based network diagram"""
        networks = self.get_networks()
        
        diagram = []
        diagram.append("=" * 80)
        diagram.append("DOCKER NETWORK TOPOLOGY")
        diagram.append("=" * 80)
        
        for network in networks:
            diagram.append(f"\n📡 Network: {network['name']}")
            diagram.append(f"   Subnet: {network['subnet']}")
            diagram.append(f"   Gateway: {network['gateway']}")
            diagram.append(f"   Containers:")
            
            for container in network['containers']:
                diagram.append(f"      • {container['name']} ({container['ipv4']})")
        
        diagram.append("\n" + "=" * 80)
        
        return "\n".join(diagram)
    
    def export_to_json(self, output_file: str):
        """Export full inspection results to JSON"""
        data = {
            'networks': self.get_networks(),
            'containers': self.get_containers(),
            'ssrf_targets': self.find_ssrf_targets()
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Exported to {output_file}")
    
    def get_compose_services(self, compose_file: str = 'docker-compose.yml') -> Dict:
        """Parse docker-compose.yml để lấy service definitions"""
        try:
            import yaml
            
            with open(compose_file, 'r') as f:
                compose_data = yaml.safe_load(f)
            
            services = compose_data.get('services', {})
            networks = compose_data.get('networks', {})
            
            return {
                'services': services,
                'networks': networks
            }
        except Exception as e:
            print(f"[!] Could not parse docker-compose.yml: {e}")
            return {}

if __name__ == "__main__":
    # Test
    inspector = DockerInspector()
    
    if inspector.is_available:
        print(inspector.generate_network_diagram())
        
        print("\n🎯 SSRF Attack Targets:")
        targets = inspector.find_ssrf_targets()
        for i, target in enumerate(targets, 1):
            print(f"{i}. {target['attack_scenario']}")
        
        inspector.export_to_json("docker_inspection.json")
    else:
        print("[!] Docker is not available")
