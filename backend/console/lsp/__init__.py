"""LSP ViewPath: read-only Junos MPLS/RSVP discovery and topology.

This package never opens SSH itself. It uses the existing Netmiko MCP client
(``StdioMCPClient`` / ``ssh_execute_many`` / ``ssh_read_output``) and only runs
``show`` / ``display set`` commands. Every topology fact carries an evidence
reference back to the raw CLI output saved by the Web Console.
"""

from .parser import (
    parse_config_interfaces_set,
    parse_config_set,
    parse_interface_descriptions,
    parse_interfaces_terse,
    parse_isis_adjacency,
    parse_lldp_neighbors,
    parse_mpls_lsp_extensive,
    parse_planned_ticket,
    parse_rsvp_interface,
    parse_rsvp_session_extensive,
)
from .service import LspService, LspValidationError, LspNotFound
from .topology import build_topology

__all__ = [
    "LspService",
    "LspValidationError",
    "LspNotFound",
    "build_topology",
    "parse_config_interfaces_set",
    "parse_config_set",
    "parse_interface_descriptions",
    "parse_interfaces_terse",
    "parse_isis_adjacency",
    "parse_lldp_neighbors",
    "parse_mpls_lsp_extensive",
    "parse_planned_ticket",
    "parse_rsvp_interface",
    "parse_rsvp_session_extensive",
]
