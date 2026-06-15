"""
=============================================================================
Honeypot Manager
=============================================================================
Deploys and destroys honeypot Docker containers on-demand.
Creates isolated Docker network with no internet access.
=============================================================================
"""

import logging
import threading
from typing import Dict, Optional

import docker
from docker.errors import DockerException, NotFound, APIError

from .models import HoneypotInstance
from .config import config

logger = logging.getLogger("orchestrator.honeypot_manager")


class HoneypotManager:
    """
    Manages the lifecycle of honeypot Docker containers.
    Creates an isolated network and deploys containers with resource limits.
    """

    def __init__(self):
        self._client: Optional[docker.DockerClient] = None
        self._network = None
        self._active_honeypots: Dict[str, HoneypotInstance] = {}  # ip → instance
        self._ip_counter = 10  # Start assigning from 172.20.0.10
        self._lock = threading.Lock()
        self._initialize()

    def _initialize(self):
        """Initialize Docker client and ensure deception network exists."""
        try:
            self._client = docker.from_env()
            self._client.ping()
            logger.info("Docker client initialized successfully")
            self._ensure_network()
        except DockerException as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            logger.warning("Honeypot manager running in degraded mode (no Docker)")
            self._client = None

    def _ensure_network(self):
        """Create the deception network if it doesn't exist."""
        if self._client is None:
            return

        network_name = config.HONEYPOT_NETWORK
        try:
            # Check if network already exists
            existing = self._client.networks.list(names=[network_name])
            if existing:
                self._network = existing[0]
                logger.info(f"Using existing network: {network_name}")
                return

            # Create isolated network (no internet access)
            ipam_pool = docker.types.IPAMPool(
                subnet="172.20.0.0/16",
                gateway="172.20.0.1",
            )
            ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])

            self._network = self._client.networks.create(
                name=network_name,
                driver="bridge",
                internal=True,  # NO internet access
                ipam=ipam_config,
                labels={"deception-soc": "network"},
            )
            logger.info(
                f"Created isolated network: {network_name} "
                f"(subnet=172.20.0.0/16, internal=True)"
            )
        except DockerException as e:
            logger.error(f"Failed to create/find network: {e}")

    def _get_next_ip(self) -> str:
        """Assign the next available IP address from the honeypot subnet."""
        with self._lock:
            ip = f"{config.HONEYPOT_SUBNET}.{self._ip_counter}"
            self._ip_counter += 1
            if self._ip_counter > 254:
                self._ip_counter = 10  # Wrap around
            return ip

    def _get_image_name(self, attack_type: str) -> str:
        """Get the Docker image name for a given attack type."""
        return config.HONEYPOT_IMAGES.get(attack_type, config.HONEYPOT_IMAGES["multi"])

    def deploy_honeypot(
        self,
        attack_type: str,
        target_port: int,
        attacker_ip: str,
    ) -> Optional[HoneypotInstance]:
        """
        Deploy a new honeypot container for the specified attack type.

        Args:
            attack_type: Type of honeypot to deploy (ssh, http, ftp, multi)
            target_port: The port the attacker was targeting
            attacker_ip: The attacker's source IP address

        Returns:
            HoneypotInstance if successful, None otherwise
        """
        if self._client is None:
            logger.error("Docker client not available — cannot deploy honeypot")
            return None

        # Check max honeypot limit
        if len(self._active_honeypots) >= config.MAX_HONEYPOTS:
            logger.warning(
                f"Maximum honeypot limit reached ({config.MAX_HONEYPOTS}). "
                f"Cannot deploy new honeypot."
            )
            return None

        honeypot_ip = self._get_next_ip()
        image_name = self._get_image_name(attack_type)

        # Determine the service port based on attack type
        service_port_map = {"ssh": 22, "http": 80, "ftp": 21, "multi": target_port}
        service_port = service_port_map.get(attack_type, target_port)

        logger.info(
            f"Deploying honeypot: type={attack_type}, image={image_name}, "
            f"ip={honeypot_ip}, port={service_port}, attacker={attacker_ip}"
        )

        try:
            # Network configuration with specific IP
            networking_config = {
                config.HONEYPOT_NETWORK: self._client.api.create_endpoint_config(
                    ipv4_address=honeypot_ip
                )
            }

            container = self._client.containers.run(
                image=image_name,
                detach=True,
                name=f"honeypot-{attack_type}-{honeypot_ip.replace('.', '-')}",
                environment={
                    "ATTACKER_IP": attacker_ip,
                    "SERVICE_PORT": str(service_port),
                    "LOGGER_URL": config.LOGGER_URL,
                    "HONEYPOT_TYPE": attack_type,
                },
                labels={
                    "deception-soc": "honeypot",
                    "attacker-ip": attacker_ip,
                    "service-type": attack_type,
                    "honeypot-ip": honeypot_ip,
                },
                mem_limit=config.HONEYPOT_MEM_LIMIT,
                cpu_period=config.HONEYPOT_CPU_PERIOD,
                cpu_quota=config.HONEYPOT_CPU_QUOTA,
                security_opt=["no-new-privileges"],
                network=config.HONEYPOT_NETWORK,
                networking_config=networking_config,
                auto_remove=False,
            )

            instance = HoneypotInstance(
                container_id=container.id,
                ip=honeypot_ip,
                port=service_port,
                service_type=attack_type,
            )

            with self._lock:
                self._active_honeypots[honeypot_ip] = instance

            logger.info(
                f"Honeypot deployed successfully: "
                f"container={container.short_id}, ip={honeypot_ip}"
            )
            return instance

        except docker.errors.ImageNotFound:
            logger.error(
                f"Docker image not found: {image_name}. "
                f"Please build honeypot images first."
            )
            return None
        except APIError as e:
            logger.error(f"Docker API error deploying honeypot: {e}")
            return None
        except DockerException as e:
            logger.error(f"Docker error deploying honeypot: {e}")
            return None

    def destroy_honeypot(self, honeypot_ip: str) -> bool:
        """
        Destroy a honeypot container and clean up resources.

        Args:
            honeypot_ip: The IP address of the honeypot to destroy

        Returns:
            True if successfully destroyed, False otherwise
        """
        if self._client is None:
            logger.error("Docker client not available")
            return False

        instance = self._active_honeypots.get(honeypot_ip)
        if instance is None:
            logger.warning(f"No active honeypot found at {honeypot_ip}")
            return False

        logger.info(
            f"Destroying honeypot: ip={honeypot_ip}, "
            f"container={instance.container_id[:12]}"
        )

        try:
            container = self._client.containers.get(instance.container_id)

            # Save container logs before stopping
            try:
                logs = container.logs(tail=1000).decode("utf-8", errors="replace")
                logger.info(
                    f"Saved {len(logs)} bytes of logs from honeypot {honeypot_ip}"
                )
            except Exception as e:
                logger.warning(f"Could not save container logs: {e}")

            # Stop and remove the container
            container.stop(timeout=5)
            container.remove(force=True)

            logger.info(f"Honeypot container destroyed: {honeypot_ip}")

        except NotFound:
            logger.warning(
                f"Container {instance.container_id[:12]} not found "
                f"(may have already been removed)"
            )
        except DockerException as e:
            logger.error(f"Error destroying honeypot container: {e}")
            return False
        finally:
            # Always clean up tracking
            with self._lock:
                self._active_honeypots.pop(honeypot_ip, None)

        return True

    def get_active_honeypots(self) -> Dict[str, HoneypotInstance]:
        """Return a copy of the active honeypots dictionary."""
        with self._lock:
            return dict(self._active_honeypots)

    def get_honeypot(self, honeypot_ip: str) -> Optional[HoneypotInstance]:
        """Get a specific honeypot instance by IP."""
        return self._active_honeypots.get(honeypot_ip)

    def cleanup_all(self) -> int:
        """Destroy all active honeypots. Returns count of destroyed containers."""
        ips = list(self._active_honeypots.keys())
        destroyed = 0
        for ip in ips:
            if self.destroy_honeypot(ip):
                destroyed += 1
        logger.info(f"Cleaned up {destroyed}/{len(ips)} honeypots")
        return destroyed
