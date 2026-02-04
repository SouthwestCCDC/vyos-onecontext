"""System configuration models (conntrack, etc.)."""

from typing import Annotated, Literal

from pydantic import BaseModel, Field, model_validator


class ConntrackTimeoutRule(BaseModel):
    """Conntrack timeout custom rule for connection tracking timeout configuration.

    Allows customization of connection tracking timeouts for specific traffic patterns.
    Useful for IP hopping scenarios where short idle timeouts force connection remapping.
    """

    description: Annotated[
        str | None, Field(None, description="Rule description")
    ]
    source_address: Annotated[
        str | None, Field(None, description="Source CIDR to match")
    ]
    destination_address: Annotated[
        str | None, Field(None, description="Destination CIDR to match")
    ]
    protocol: Annotated[
        Literal["tcp", "udp", "icmp"], Field(description="Protocol to match")
    ]
    # TCP-specific timeout options
    tcp_close: Annotated[
        int | None, Field(None, ge=1, description="TCP close timeout (seconds)")
    ]
    tcp_close_wait: Annotated[
        int | None, Field(None, ge=1, description="TCP close-wait timeout (seconds)")
    ]
    tcp_established: Annotated[
        int | None, Field(None, ge=1, description="TCP established timeout (seconds)")
    ]
    tcp_fin_wait: Annotated[
        int | None, Field(None, ge=1, description="TCP fin-wait timeout (seconds)")
    ]
    tcp_last_ack: Annotated[
        int | None, Field(None, ge=1, description="TCP last-ack timeout (seconds)")
    ]
    tcp_syn_recv: Annotated[
        int | None, Field(None, ge=1, description="TCP syn-recv timeout (seconds)")
    ]
    tcp_syn_sent: Annotated[
        int | None, Field(None, ge=1, description="TCP syn-sent timeout (seconds)")
    ]
    tcp_time_wait: Annotated[
        int | None, Field(None, ge=1, description="TCP time-wait timeout (seconds)")
    ]
    # UDP-specific timeout options
    udp_other: Annotated[
        int | None, Field(None, ge=1, description="UDP other timeout (seconds)")
    ]
    udp_stream: Annotated[
        int | None, Field(None, ge=1, description="UDP stream timeout (seconds)")
    ]
    # ICMP-specific timeout option
    icmp_timeout: Annotated[
        int | None, Field(None, ge=1, description="ICMP timeout (seconds)")
    ]

    @model_validator(mode="after")
    def validate_protocol_specific_timeouts(self) -> "ConntrackTimeoutRule":
        """Ensure protocol-specific timeout fields match the protocol."""
        tcp_fields = {
            "tcp_close", "tcp_close_wait", "tcp_established", "tcp_fin_wait",
            "tcp_last_ack", "tcp_syn_recv", "tcp_syn_sent", "tcp_time_wait"
        }
        udp_fields = {"udp_other", "udp_stream"}
        icmp_fields = {"icmp_timeout"}

        # Check for protocol mismatches
        if self.protocol == "tcp":
            for field in udp_fields | icmp_fields:
                if getattr(self, field) is not None:
                    raise ValueError(
                        f"Field '{field}' is not valid for protocol 'tcp'"
                    )
        elif self.protocol == "udp":
            for field in tcp_fields | icmp_fields:
                if getattr(self, field) is not None:
                    raise ValueError(
                        f"Field '{field}' is not valid for protocol 'udp'"
                    )
        elif self.protocol == "icmp":
            for field in tcp_fields | udp_fields:
                if getattr(self, field) is not None:
                    raise ValueError(
                        f"Field '{field}' is not valid for protocol 'icmp'"
                    )

        # Ensure at least one timeout field is set for the protocol
        if self.protocol == "tcp":
            if not any(getattr(self, field) is not None for field in tcp_fields):
                raise ValueError("At least one TCP timeout field must be set")
        elif self.protocol == "udp":
            if not any(getattr(self, field) is not None for field in udp_fields):
                raise ValueError("At least one UDP timeout field must be set")
        elif self.protocol == "icmp" and self.icmp_timeout is None:
            raise ValueError("ICMP timeout field must be set")

        return self


class ConntrackConfig(BaseModel):
    """Conntrack configuration.

    Contains custom timeout rules for connection tracking.
    """

    timeout_rules: list[ConntrackTimeoutRule] = Field(
        default_factory=list, description="Custom timeout rules"
    )
