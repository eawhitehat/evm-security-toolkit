"""
Configuration management for EVM Security Toolkit.
"""

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    """Global configuration loaded from environment variables."""

    # RPC endpoints
    eth_rpc: str = os.getenv("ETH_RPC_URL", "https://eth.llamarpc.com")
    bsc_rpc: str = os.getenv("BSC_RPC_URL", "https://bsc-dataseed1.binance.org")
    polygon_rpc: str = os.getenv("POLYGON_RPC_URL", "https://polygon-rpc.com")
    arbitrum_rpc: str = os.getenv("ARBITRUM_RPC_URL", "https://arb1.arbitrum.io/rpc")
    base_rpc: str = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")

    # Explorer API keys
    etherscan_key: str = os.getenv("ETHERSCAN_API_KEY", "")
    bscscan_key: str = os.getenv("BSCSCAN_API_KEY", "")

    def get_rpc(self, chain: str) -> str:
        rpcs = {
            "ethereum": self.eth_rpc,
            "bsc": self.bsc_rpc,
            "polygon": self.polygon_rpc,
            "arbitrum": self.arbitrum_rpc,
            "base": self.base_rpc,
        }
        return rpcs.get(chain, self.eth_rpc)

    def get_api_key(self, chain: str) -> str:
        keys = {
            "ethereum": self.etherscan_key,
            "bsc": self.bscscan_key,
        }
        return keys.get(chain, "")
