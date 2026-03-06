from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from heapq import nlargest
from typing import Iterable

from django.db import connection, transaction

from .models import CorrelatedFlow, FlowLogEntry, IpMetadata, NetworkGroup
from .parsers import ParsedFlowRecord

KNOWN_SERVER_PORTS = {
    20,
    21,
    22,
    25,
    53,
    80,
    110,
    123,
    143,
    443,
    3306,
    5432,
    6379,
    8080,
    8443,
}
FIREWALL_SIM_GROUP_TAG = "firewall-simulator"
FIREWALL_SIM_SOURCE_PREFIX = "[FIREWALL_SIM_SOURCE]"
SQLITE_IN_CLAUSE_LIMIT = 900


def _iter_chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(items), size):
        yield items[index:index + size]


def _iter_flows(flows: Iterable[CorrelatedFlow], *, chunk_size: int = 2000):
    iterator = getattr(flows, "iterator", None)
    if callable(iterator):
        yield from iterator(chunk_size=chunk_size)
        return
    yield from flows


def protocol_to_name(protocol: int) -> str:
    if protocol == 6:
        return "tcp"
    if protocol == 17:
        return "udp"
    if protocol == 1:
        return "icmp"
    if protocol == 4:
        return "ipip"
    return str(protocol)


def ip_to_host_cidr(ip_text: str) -> str:
    ip_obj = ipaddress.ip_address(ip_text)
    return f"{ip_text}/32" if ip_obj.version == 4 else f"{ip_text}/128"


def infer_client_server(
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
) -> tuple[str, int | None, str, int | None]:
    if src_port is None or dst_port is None:
        return src_ip, src_port, dst_ip, dst_port

    if dst_port in KNOWN_SERVER_PORTS and src_port not in KNOWN_SERVER_PORTS:
        return src_ip, src_port, dst_ip, dst_port

    if src_port in KNOWN_SERVER_PORTS and dst_port not in KNOWN_SERVER_PORTS:
        return dst_ip, dst_port, src_ip, src_port

    if src_port > dst_port:
        return src_ip, src_port, dst_ip, dst_port

    if dst_port > src_port:
        return dst_ip, dst_port, src_ip, src_port

    if src_ip <= dst_ip:
        return src_ip, src_port, dst_ip, dst_port

    return dst_ip, dst_port, src_ip, src_port


def make_canonical_key(
    client_ip: str,
    client_port: int | None,
    server_ip: str,
    server_port: int | None,
    protocol: int,
) -> str:
    return f"{client_ip}:{client_port or 0}>{server_ip}:{server_port or 0}/p{protocol}"


@dataclass
class CorrelatedAccumulator:
    canonical_key: str
    client_ip: str
    server_ip: str
    client_port: int | None
    server_port: int | None
    protocol: int
    flow_count: int = 0
    c2s_packets: int = 0
    c2s_bytes: int = 0
    s2c_packets: int = 0
    s2c_bytes: int = 0
    first_seen: object | None = None
    last_seen: object | None = None
    action_counts: dict[str, int] = field(default_factory=dict)


def parsed_records_to_entries(records: Iterable[ParsedFlowRecord], source: str = "") -> list[FlowLogEntry]:
    entries: list[FlowLogEntry] = []
    for record in records:
        entries.append(
            FlowLogEntry(
                version=record.version,
                account_id=record.account_id,
                interface_id=record.interface_id,
                srcaddr=record.srcaddr,
                dstaddr=record.dstaddr,
                srcport=record.srcport,
                dstport=record.dstport,
                protocol=record.protocol,
                packets=record.packets,
                bytes=record.bytes,
                start_time=record.start_time,
                end_time=record.end_time,
                action=record.action,
                log_status=record.log_status,
                source=source,
                raw_line=record.raw_line,
            )
        )
    return entries


def _aggregate_entries(entries: Iterable[FlowLogEntry]) -> dict[str, CorrelatedAccumulator]:
    aggregated: dict[str, CorrelatedAccumulator] = {}

    for entry in entries:
        client_ip, client_port, server_ip, server_port = infer_client_server(
            entry.srcaddr,
            entry.srcport,
            entry.dstaddr,
            entry.dstport,
        )

        canonical_key = make_canonical_key(client_ip, client_port, server_ip, server_port, entry.protocol)

        acc = aggregated.get(canonical_key)
        if acc is None:
            acc = CorrelatedAccumulator(
                canonical_key=canonical_key,
                client_ip=client_ip,
                server_ip=server_ip,
                client_port=client_port,
                server_port=server_port,
                protocol=entry.protocol,
                first_seen=entry.start_time,
                last_seen=entry.end_time,
            )
            aggregated[canonical_key] = acc

        acc.flow_count += 1
        acc.first_seen = min(acc.first_seen, entry.start_time) if acc.first_seen else entry.start_time
        acc.last_seen = max(acc.last_seen, entry.end_time) if acc.last_seen else entry.end_time

        is_c2s = (
            entry.srcaddr == client_ip
            and entry.dstaddr == server_ip
            and entry.srcport == client_port
            and entry.dstport == server_port
        )

        if is_c2s:
            acc.c2s_packets += entry.packets
            acc.c2s_bytes += entry.bytes
        else:
            acc.s2c_packets += entry.packets
            acc.s2c_bytes += entry.bytes

        action_key = (entry.action or "UNKNOWN").upper()
        acc.action_counts[action_key] = acc.action_counts.get(action_key, 0) + 1

    return aggregated


_PG_UPSERT_BATCH_SIZE = 500

_PG_UPSERT_SQL = """
    INSERT INTO flows_correlatedflow (
        canonical_key, client_ip, server_ip, client_port, server_port,
        protocol, flow_count, c2s_packets, c2s_bytes, s2c_packets, s2c_bytes,
        first_seen, last_seen, action_counts, updated_at
    )
    VALUES {placeholders}
    ON CONFLICT (canonical_key) DO UPDATE SET
        flow_count   = flows_correlatedflow.flow_count   + EXCLUDED.flow_count,
        c2s_packets  = flows_correlatedflow.c2s_packets  + EXCLUDED.c2s_packets,
        c2s_bytes    = flows_correlatedflow.c2s_bytes    + EXCLUDED.c2s_bytes,
        s2c_packets  = flows_correlatedflow.s2c_packets  + EXCLUDED.s2c_packets,
        s2c_bytes    = flows_correlatedflow.s2c_bytes    + EXCLUDED.s2c_bytes,
        first_seen   = LEAST(flows_correlatedflow.first_seen, EXCLUDED.first_seen),
        last_seen    = GREATEST(flows_correlatedflow.last_seen, EXCLUDED.last_seen),
        action_counts = (
            SELECT COALESCE(jsonb_object_agg(key, total), '{{}}'::jsonb)
            FROM (
                SELECT key, SUM(value::bigint) AS total
                FROM (
                    SELECT key, value
                      FROM jsonb_each_text(flows_correlatedflow.action_counts)
                    UNION ALL
                    SELECT key, value
                      FROM jsonb_each_text(EXCLUDED.action_counts)
                ) _combined
                GROUP BY key
            ) _merged
        ),
        updated_at = NOW()
"""

_PG_ROW_PLACEHOLDER = (
    "(%s, %s::inet, %s::inet, %s, %s, %s, %s, %s, %s, %s, %s,"
    " %s::timestamptz, %s::timestamptz, %s::jsonb, NOW())"
)


def _pg_upsert_correlated(aggregated: dict[str, CorrelatedAccumulator]) -> dict[str, int]:
    items = list(aggregated.values())
    total = 0

    with connection.cursor() as cursor:
        for start in range(0, len(items), _PG_UPSERT_BATCH_SIZE):
            chunk = items[start:start + _PG_UPSERT_BATCH_SIZE]
            placeholders = []
            params: list = []

            for acc in chunk:
                placeholders.append(_PG_ROW_PLACEHOLDER)
                params.extend([
                    acc.canonical_key,
                    acc.client_ip,
                    acc.server_ip,
                    acc.client_port,
                    acc.server_port,
                    acc.protocol,
                    acc.flow_count,
                    acc.c2s_packets,
                    acc.c2s_bytes,
                    acc.s2c_packets,
                    acc.s2c_bytes,
                    acc.first_seen,
                    acc.last_seen,
                    json.dumps(acc.action_counts),
                ])

            sql = _PG_UPSERT_SQL.format(placeholders=", ".join(placeholders))
            cursor.execute(sql, params)
            total += cursor.rowcount

    return {"created": total, "updated": 0}


def _sqlite_upsert_correlated(aggregated: dict[str, CorrelatedAccumulator]) -> dict[str, int]:
    keys = list(aggregated.keys())
    existing: dict[str, CorrelatedFlow] = {}
    for key_chunk in _iter_chunks(keys, SQLITE_IN_CLAUSE_LIMIT):
        for item in CorrelatedFlow.objects.filter(canonical_key__in=key_chunk):
            existing[item.canonical_key] = item

    to_create: list[CorrelatedFlow] = []
    to_update: list[CorrelatedFlow] = []

    for key, acc in aggregated.items():
        current = existing.get(key)
        if current is None:
            to_create.append(
                CorrelatedFlow(
                    canonical_key=key,
                    client_ip=acc.client_ip,
                    server_ip=acc.server_ip,
                    client_port=acc.client_port,
                    server_port=acc.server_port,
                    protocol=acc.protocol,
                    flow_count=acc.flow_count,
                    c2s_packets=acc.c2s_packets,
                    c2s_bytes=acc.c2s_bytes,
                    s2c_packets=acc.s2c_packets,
                    s2c_bytes=acc.s2c_bytes,
                    first_seen=acc.first_seen,
                    last_seen=acc.last_seen,
                    action_counts=acc.action_counts,
                )
            )
            continue

        current.flow_count += acc.flow_count
        current.c2s_packets += acc.c2s_packets
        current.c2s_bytes += acc.c2s_bytes
        current.s2c_packets += acc.s2c_packets
        current.s2c_bytes += acc.s2c_bytes
        current.first_seen = min(current.first_seen, acc.first_seen)
        current.last_seen = max(current.last_seen, acc.last_seen)

        merged_action_counts = dict(current.action_counts)
        for action_key, count in acc.action_counts.items():
            merged_action_counts[action_key] = merged_action_counts.get(action_key, 0) + count
        current.action_counts = merged_action_counts
        to_update.append(current)

    if to_create:
        CorrelatedFlow.objects.bulk_create(to_create, batch_size=1000)
    if to_update:
        CorrelatedFlow.objects.bulk_update(
            to_update,
            fields=[
                "flow_count", "c2s_packets", "c2s_bytes",
                "s2c_packets", "s2c_bytes", "first_seen",
                "last_seen", "action_counts", "updated_at",
            ],
            batch_size=1000,
        )

    return {"created": len(to_create), "updated": len(to_update)}


@transaction.atomic
def upsert_correlated_flows(entries: Iterable[FlowLogEntry]) -> dict[str, int]:
    aggregated = _aggregate_entries(entries)
    if not aggregated:
        return {"created": 0, "updated": 0}

    if connection.vendor == "sqlite":
        return _sqlite_upsert_correlated(aggregated)
    return _pg_upsert_correlated(aggregated)


def rebuild_correlated_flows(batch_size: int = 2000) -> dict[str, int]:
    with transaction.atomic():
        CorrelatedFlow.objects.all().delete()

    created_total = 0
    updated_total = 0
    buffer: list[FlowLogEntry] = []

    for entry in FlowLogEntry.objects.order_by("id").iterator(chunk_size=batch_size):
        buffer.append(entry)
        if len(buffer) >= batch_size:
            stats = upsert_correlated_flows(buffer)
            created_total += stats["created"]
            updated_total += stats["updated"]
            buffer.clear()

    if buffer:
        stats = upsert_correlated_flows(buffer)
        created_total += stats["created"]
        updated_total += stats["updated"]

    return {"created": created_total, "updated": updated_total}


def _is_firewall_sim_group(group: NetworkGroup) -> bool:
    tags = group.tags
    if isinstance(tags, list):
        for raw_tag in tags:
            if str(raw_tag).strip().lower() == FIREWALL_SIM_GROUP_TAG:
                return True

    description = str(group.description or "").strip()
    if description and FIREWALL_SIM_SOURCE_PREFIX in description:
        return True

    return False


def _load_network_group_index(*, exclude_firewall_sim: bool = False) -> list[tuple[NetworkGroup, ipaddress._BaseNetwork]]:
    indexed: list[tuple[NetworkGroup, ipaddress._BaseNetwork]] = []
    for group in NetworkGroup.objects.all():
        if exclude_firewall_sim and _is_firewall_sim_group(group):
            continue
        for cidr in group.cidr_values:
            try:
                indexed.append((group, ipaddress.ip_network(cidr, strict=False)))
            except ValueError:
                continue
    return indexed


def _find_group_match_for_ip(
    ip_text: str,
    groups: list[tuple[NetworkGroup, ipaddress._BaseNetwork]],
) -> tuple[NetworkGroup, ipaddress._BaseNetwork] | None:
    ip_obj = ipaddress.ip_address(ip_text)
    matching: list[tuple[NetworkGroup, ipaddress._BaseNetwork]] = [item for item in groups if ip_obj in item[1]]
    if not matching:
        return None
    matching.sort(key=lambda item: item[1].prefixlen, reverse=True)
    return matching[0]


def _find_group_for_ip(ip_text: str, groups: list[tuple[NetworkGroup, ipaddress._BaseNetwork]]) -> NetworkGroup | None:
    match = _find_group_match_for_ip(ip_text, groups)
    if match is None:
        return None
    return match[0]


def _label_for_ip(ip_text: str, metadata_by_ip: dict[str, IpMetadata]) -> str:
    metadata = metadata_by_ip.get(ip_text)
    if metadata and metadata.name:
        return metadata.name
    return ip_text


def _tag_map(value) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): "" if tag_value is None else str(tag_value) for key, tag_value in value.items()}
    if isinstance(value, list):
        payload: dict[str, str] = {}
        for item in value:
            text = str(item).strip()
            if not text:
                continue
            if "=" in text:
                key, tag_value = text.split("=", 1)
                payload[key.strip()] = tag_value.strip()
            else:
                payload[text] = ""
        return payload
    return {}


def build_mesh_payload(
    flows: Iterable[CorrelatedFlow],
    *,
    edge_limit: int | None = None,
) -> dict[str, list[dict]]:
    metadata_by_ip = {meta.ip_address: meta for meta in IpMetadata.objects.all()}
    network_groups = _load_network_group_index(exclude_firewall_sim=True)

    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}

    for flow in _iter_flows(flows):
        consumer_ip = flow.client_ip
        provider_ip = flow.server_ip

        consumer_label = _label_for_ip(consumer_ip, metadata_by_ip)
        provider_label = _label_for_ip(provider_ip, metadata_by_ip)

        consumer_group = _find_group_for_ip(consumer_ip, network_groups)
        provider_group = _find_group_for_ip(provider_ip, network_groups)

        total_bytes = flow.c2s_bytes + flow.s2c_bytes
        total_packets = flow.c2s_packets + flow.s2c_packets

        if consumer_ip not in nodes:
            consumer_meta = metadata_by_ip.get(consumer_ip)
            nodes[consumer_ip] = {
                "id": consumer_ip,
                "label": consumer_label,
                "ip": consumer_ip,
                "role": "consumer",
                "asset_kind": consumer_meta.asset_kind if consumer_meta else IpMetadata.KIND_UNKNOWN,
                "instance_id": consumer_meta.instance_id if consumer_meta else "",
                "interface_id": consumer_meta.interface_id if consumer_meta else "",
                "instance_type": consumer_meta.instance_type if consumer_meta else "",
                "state": consumer_meta.state if consumer_meta else "",
                "region": consumer_meta.region if consumer_meta else "",
                "availability_zone": consumer_meta.availability_zone if consumer_meta else "",
                "account_owner": consumer_meta.account_owner if consumer_meta else "",
                "provider": consumer_meta.provider if consumer_meta else "",
                "tags": _tag_map(consumer_meta.tags if consumer_meta else {}),
                "group": consumer_group.name if consumer_group else "",
                "bytes_in": 0,
                "bytes_out": 0,
                "packets_in": 0,
                "packets_out": 0,
            }
        elif nodes[consumer_ip]["role"] == "provider":
            nodes[consumer_ip]["role"] = "mixed"

        if provider_ip not in nodes:
            provider_meta = metadata_by_ip.get(provider_ip)
            nodes[provider_ip] = {
                "id": provider_ip,
                "label": provider_label,
                "ip": provider_ip,
                "role": "provider",
                "asset_kind": provider_meta.asset_kind if provider_meta else IpMetadata.KIND_UNKNOWN,
                "instance_id": provider_meta.instance_id if provider_meta else "",
                "interface_id": provider_meta.interface_id if provider_meta else "",
                "instance_type": provider_meta.instance_type if provider_meta else "",
                "state": provider_meta.state if provider_meta else "",
                "region": provider_meta.region if provider_meta else "",
                "availability_zone": provider_meta.availability_zone if provider_meta else "",
                "account_owner": provider_meta.account_owner if provider_meta else "",
                "provider": provider_meta.provider if provider_meta else "",
                "tags": _tag_map(provider_meta.tags if provider_meta else {}),
                "group": provider_group.name if provider_group else "",
                "bytes_in": 0,
                "bytes_out": 0,
                "packets_in": 0,
                "packets_out": 0,
            }
        elif nodes[provider_ip]["role"] == "consumer":
            nodes[provider_ip]["role"] = "mixed"

        nodes[consumer_ip]["bytes_out"] += flow.c2s_bytes
        nodes[consumer_ip]["bytes_in"] += flow.s2c_bytes
        nodes[consumer_ip]["packets_out"] += flow.c2s_packets
        nodes[consumer_ip]["packets_in"] += flow.s2c_packets

        nodes[provider_ip]["bytes_in"] += flow.c2s_bytes
        nodes[provider_ip]["bytes_out"] += flow.s2c_bytes
        nodes[provider_ip]["packets_in"] += flow.c2s_packets
        nodes[provider_ip]["packets_out"] += flow.s2c_packets

        edge_key = (consumer_ip, provider_ip, flow.protocol, flow.server_port)
        edge = edges.get(edge_key)
        if edge is None:
            edge = {
                "source": consumer_ip,
                "target": provider_ip,
                "source_label": consumer_label,
                "target_label": provider_label,
                "protocol": flow.protocol,
                "protocol_name": protocol_to_name(flow.protocol),
                "port": flow.server_port,
                "bytes": 0,
                "packets": 0,
                "flows": 0,
            }
            edges[edge_key] = edge

        edge["bytes"] += total_bytes
        edge["packets"] += total_packets
        edge["flows"] += flow.flow_count

    if edge_limit is not None and edge_limit > 0:
        sorted_nodes = list(nodes.values())
    else:
        sorted_nodes = sorted(nodes.values(), key=lambda item: item["bytes_in"] + item["bytes_out"], reverse=True)
    if edge_limit is not None and edge_limit > 0:
        sorted_edges = nlargest(edge_limit, edges.values(), key=lambda item: item["bytes"])
    else:
        sorted_edges = sorted(edges.values(), key=lambda item: item["bytes"], reverse=True)

    return {"nodes": sorted_nodes, "edges": sorted_edges}


def build_firewall_recommendations(
    flows: Iterable[CorrelatedFlow],
    *,
    min_bytes: int = 0,
) -> list[dict]:
    metadata_by_ip = {meta.ip_address: meta for meta in IpMetadata.objects.all()}
    network_groups = _load_network_group_index()

    aggregated_rules: dict[tuple, dict] = {}

    for flow in _iter_flows(flows):
        total_bytes = flow.c2s_bytes + flow.s2c_bytes
        if total_bytes < min_bytes:
            continue

        source_match = _find_group_match_for_ip(flow.client_ip, network_groups)
        dest_match = _find_group_match_for_ip(flow.server_ip, network_groups)

        source = str(source_match[1]) if source_match else ip_to_host_cidr(flow.client_ip)
        destination = str(dest_match[1]) if dest_match else ip_to_host_cidr(flow.server_ip)

        protocol_name = protocol_to_name(flow.protocol)
        port_value = flow.server_port if flow.server_port is not None else "*"

        key = (source, destination, protocol_name, port_value)
        rule = aggregated_rules.get(key)
        if rule is None:
            rule = {
                "source": source,
                "destination": destination,
                "protocol": protocol_name,
                "port": port_value,
                "bytes": 0,
                "packets": 0,
                "flows": 0,
                "first_seen": flow.first_seen,
                "last_seen": flow.last_seen,
                "consumer_examples": [],
                "provider_examples": [],
            }
            aggregated_rules[key] = rule

        rule["bytes"] += total_bytes
        rule["packets"] += flow.c2s_packets + flow.s2c_packets
        rule["flows"] += flow.flow_count
        rule["first_seen"] = min(rule["first_seen"], flow.first_seen)
        rule["last_seen"] = max(rule["last_seen"], flow.last_seen)

        consumer_label = _label_for_ip(flow.client_ip, metadata_by_ip)
        provider_label = _label_for_ip(flow.server_ip, metadata_by_ip)

        if consumer_label not in rule["consumer_examples"] and len(rule["consumer_examples"]) < 5:
            rule["consumer_examples"].append(consumer_label)
        if provider_label not in rule["provider_examples"] and len(rule["provider_examples"]) < 5:
            rule["provider_examples"].append(provider_label)

    return sorted(aggregated_rules.values(), key=lambda item: item["bytes"], reverse=True)
