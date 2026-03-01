from __future__ import annotations

import ipaddress
import json
import random
from dataclasses import dataclass
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from flows.models import CorrelatedFlow, FlowLogEntry, IpMetadata, NetworkGroup
from flows.services import rebuild_correlated_flows


SOURCE_META_PREFIX = "[FIREWALL_SIM_SOURCE]"
SIMULATOR_TAG = "firewall-simulator"


@dataclass(frozen=True)
class AssetRecord:
    ip_address: str
    name: str
    role: str
    asset_kind: str
    instance_id: str
    interface_id: str
    instance_type: str
    state: str
    region: str
    availability_zone: str
    account_owner: str
    provider: str
    tags: dict[str, str]
    attributes: dict[str, str]


@dataclass(frozen=True)
class FlowPattern:
    name: str
    source_role: str
    destination_role: str
    protocol: int
    ports: tuple[int, ...]
    weight: int
    accept_rate: float
    response_rate: float
    bytes_min: int
    bytes_max: int
    duration_min: int
    duration_max: int


def _iter_host_ips(cidr: str, *, start: int, count: int) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    if count <= 0:
        return []

    hosts = list(network.hosts())
    if start < 0 or start >= len(hosts):
        return []

    end = min(start + count, len(hosts))
    return [str(hosts[index]) for index in range(start, end)]


def _host_cidr(ip_text: str) -> str:
    ip_obj = ipaddress.ip_address(ip_text)
    suffix = 32 if ip_obj.version == 4 else 128
    return f"{ip_text}/{suffix}"


def _in_any_network(ip_text: str, cidrs: list[str]) -> bool:
    ip_obj = ipaddress.ip_address(ip_text)
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ip_obj in network:
            return True
    return False


def _make_snapshot_description(body: str, source_meta: dict) -> str:
    marker = f"{SOURCE_META_PREFIX} {json.dumps(source_meta, separators=(',', ':'))}"
    base = body.strip()
    if not base:
        return marker
    return f"{base}\n{marker}"


class Command(BaseCommand):
    help = "Seed deterministic demo data (assets, groups, flow logs, correlations, and firewall snapshots)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Delete existing data first (flow logs, correlations, metadata, and network groups).",
        )
        parser.add_argument(
            "--seed",
            type=int,
            default=20260301,
            help="Random seed used for deterministic demo generation.",
        )
        parser.add_argument(
            "--days",
            type=int,
            default=14,
            help="How many days back flow timestamps should span.",
        )
        parser.add_argument(
            "--flow-pairs",
            type=int,
            default=2200,
            help="How many correlated client/server conversations to generate.",
        )
        parser.add_argument(
            "--source",
            default="demo-seed",
            help="FlowLogEntry.source label for generated flow logs.",
        )
        parser.add_argument(
            "--without-snapshots",
            action="store_true",
            help="Skip generating firewall simulator snapshot address groups.",
        )

    def handle(self, *args, **options):
        reset = bool(options["reset"])
        seed = int(options["seed"])
        days = max(1, int(options["days"]))
        flow_pairs = max(1, int(options["flow_pairs"]))
        source = str(options["source"]).strip() or "demo-seed"
        with_snapshots = not bool(options["without_snapshots"])

        rng = random.Random(seed)

        self.stdout.write(
            self.style.NOTICE(
                f"Seeding demo data with seed={seed}, days={days}, flow_pairs={flow_pairs}, source={source!r}"
            )
        )

        if reset:
            self._reset_all()
        else:
            deleted, _ = FlowLogEntry.objects.filter(source=source).delete()
            if deleted:
                self.stdout.write(f"Removed {deleted} existing flow log entries for source '{source}'.")

        groups = self._seed_static_network_groups()
        assets = self._seed_ip_metadata()
        flow_entry_count = self._seed_flow_logs(
            assets=assets,
            source=source,
            rng=rng,
            days=days,
            flow_pairs=flow_pairs,
        )

        rebuild_stats = rebuild_correlated_flows(batch_size=2000)
        snapshot_count = 0
        if with_snapshots:
            snapshot_count = self._seed_firewall_snapshot_groups(groups, assets)

        summary_lines = [
            f"Network groups: {NetworkGroup.objects.count()}",
            f"IP metadata rows: {IpMetadata.objects.count()}",
            f"Flow log entries: {FlowLogEntry.objects.count()}",
            f"Correlated flows: {CorrelatedFlow.objects.count()}",
            f"Flow entries generated in this run: {flow_entry_count}",
            f"Correlation rebuild created={rebuild_stats.get('created', 0)} updated={rebuild_stats.get('updated', 0)}",
        ]
        if with_snapshots:
            summary_lines.append(f"Firewall simulator snapshots created/updated: {snapshot_count}")

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("Demo data seed complete."))
        for line in summary_lines:
            self.stdout.write(f"  - {line}")

    def _reset_all(self) -> None:
        deleted_flows, _ = FlowLogEntry.objects.all().delete()
        deleted_corr, _ = CorrelatedFlow.objects.all().delete()
        deleted_meta, _ = IpMetadata.objects.all().delete()
        deleted_groups, _ = NetworkGroup.objects.all().delete()
        self.stdout.write(
            "Deleted existing data: "
            f"flows={deleted_flows}, correlated={deleted_corr}, metadata={deleted_meta}, groups={deleted_groups}"
        )

    def _seed_static_network_groups(self) -> dict[str, NetworkGroup]:
        group_specs = [
            {
                "name": "prod-app-subnets",
                "kind": NetworkGroup.KIND_VPC,
                "cidrs": ["10.10.0.0/20"],
                "tags": ["env=prod", "domain=app"],
                "description": "Primary application VPC subnets.",
            },
            {
                "name": "prod-data-subnets",
                "kind": NetworkGroup.KIND_VPC,
                "cidrs": ["10.20.0.0/20"],
                "tags": ["env=prod", "domain=data"],
                "description": "Datastore VPC subnets.",
            },
            {
                "name": "shared-services-subnets",
                "kind": NetworkGroup.KIND_VPC,
                "cidrs": ["10.30.0.0/20"],
                "tags": ["env=prod", "domain=shared"],
                "description": "Shared services and edge hosts.",
            },
            {
                "name": "k8s-payments-pods",
                "kind": NetworkGroup.KIND_CONTAINER,
                "cidrs": ["10.40.1.0/24"],
                "tags": ["cluster=payments", "env=prod"],
                "description": "Payments Kubernetes runtime range.",
            },
            {
                "name": "k8s-observability-pods",
                "kind": NetworkGroup.KIND_CONTAINER,
                "cidrs": ["10.40.2.0/24"],
                "tags": ["cluster=observability", "env=prod"],
                "description": "Observability Kubernetes runtime range.",
            },
            {
                "name": "k8s-analytics-pods",
                "kind": NetworkGroup.KIND_CONTAINER,
                "cidrs": ["10.40.3.0/24"],
                "tags": ["cluster=analytics", "env=prod"],
                "description": "Analytics Kubernetes runtime range.",
            },
            {
                "name": "corp-office",
                "kind": NetworkGroup.KIND_EXTERNAL,
                "cidrs": ["192.168.10.0/24"],
                "tags": ["source=onprem"],
                "description": "Corporate office network.",
            },
            {
                "name": "partner-vendor-net",
                "kind": NetworkGroup.KIND_EXTERNAL,
                "cidrs": ["172.18.50.0/24"],
                "tags": ["source=partner"],
                "description": "Partner vendor ingress CIDR.",
            },
            {
                "name": "dmz-edge",
                "kind": NetworkGroup.KIND_CUSTOM,
                "cidrs": ["10.30.10.0/24"],
                "tags": ["zone=dmz"],
                "description": "DMZ ingress and bastion systems.",
            },
        ]

        result: dict[str, NetworkGroup] = {}
        for spec in group_specs:
            group, _ = NetworkGroup.objects.update_or_create(
                name=spec["name"],
                defaults={
                    "kind": spec["kind"],
                    "cidrs": spec["cidrs"],
                    "cidr": spec["cidrs"][0],
                    "tags": spec["tags"],
                    "description": spec["description"],
                },
            )
            result[group.name] = group
        return result

    def _seed_ip_metadata(self) -> list[AssetRecord]:
        records: list[AssetRecord] = []

        def append_assets(
            *,
            cidr: str,
            start: int,
            count: int,
            name_prefix: str,
            role: str,
            team: str,
            app: str,
            tier: str,
            asset_kind: str = IpMetadata.KIND_INSTANCE,
            region: str = "us-east-1",
            availability_zone: str = "us-east-1a",
            account_owner: str = "111122223333",
            provider: str = "aws",
            instance_type: str = "t3.medium",
            state: str = "running",
            extra_tags: dict[str, str] | None = None,
            extra_attributes: dict[str, str] | None = None,
        ) -> None:
            for index, ip_text in enumerate(_iter_host_ips(cidr, start=start, count=count), start=1):
                suffix = f"{index:02d}"
                tags = {
                    "environment": "prod",
                    "team": team,
                    "app": app,
                    "tier": tier,
                    "role": role,
                }
                if extra_tags:
                    tags.update(extra_tags)

                attributes = {
                    "role": role,
                    "workload": app,
                    "criticality": "high" if tier in {"api", "db", "edge"} else "medium",
                }
                if extra_attributes:
                    attributes.update(extra_attributes)

                name = f"{name_prefix}-{suffix}"
                records.append(
                    AssetRecord(
                        ip_address=ip_text,
                        name=name,
                        role=role,
                        asset_kind=asset_kind,
                        instance_id=f"i-{name.replace('-', '')[:14]}{suffix.lower()}",
                        interface_id=f"eni-{name.replace('-', '')[:11]}{suffix.lower()}",
                        instance_type=instance_type,
                        state=state,
                        region=region,
                        availability_zone=availability_zone,
                        account_owner=account_owner,
                        provider=provider,
                        tags=tags,
                        attributes=attributes,
                    )
                )

        append_assets(
            cidr="10.10.1.0/24",
            start=10,
            count=18,
            name_prefix="payments-web",
            role="web",
            team="payments",
            app="payments",
            tier="web",
            availability_zone="us-east-1a",
        )
        append_assets(
            cidr="10.10.2.0/24",
            start=20,
            count=14,
            name_prefix="payments-api",
            role="api",
            team="payments",
            app="payments",
            tier="api",
            availability_zone="us-east-1b",
        )
        append_assets(
            cidr="10.20.1.0/24",
            start=10,
            count=8,
            name_prefix="payments-db",
            role="db",
            team="payments",
            app="payments",
            tier="db",
            instance_type="r6i.large",
            availability_zone="us-east-1c",
        )
        append_assets(
            cidr="10.20.2.0/24",
            start=30,
            count=6,
            name_prefix="payments-cache",
            role="cache",
            team="payments",
            app="payments",
            tier="cache",
            instance_type="r6g.large",
            availability_zone="us-east-1c",
        )
        append_assets(
            cidr="10.20.3.0/24",
            start=10,
            count=4,
            name_prefix="payments-mq",
            role="mq",
            team="payments",
            app="payments",
            tier="queue",
            instance_type="m6i.large",
            availability_zone="us-east-1b",
        )
        append_assets(
            cidr="10.30.2.0/24",
            start=10,
            count=3,
            name_prefix="infra-dns",
            role="dns",
            team="platform",
            app="infra",
            tier="shared",
            instance_type="t3.small",
            availability_zone="us-east-1a",
        )
        append_assets(
            cidr="10.30.2.0/24",
            start=40,
            count=2,
            name_prefix="infra-ntp",
            role="ntp",
            team="platform",
            app="infra",
            tier="shared",
            instance_type="t3.small",
            availability_zone="us-east-1a",
        )
        append_assets(
            cidr="10.30.3.0/24",
            start=10,
            count=4,
            name_prefix="obs-metrics",
            role="metrics",
            team="observability",
            app="observability",
            tier="shared",
            instance_type="t3.large",
            availability_zone="us-east-1b",
        )
        append_assets(
            cidr="10.30.10.0/24",
            start=10,
            count=3,
            name_prefix="edge-bastion",
            role="edge",
            team="platform",
            app="edge",
            tier="edge",
            instance_type="t3.small",
            availability_zone="us-east-1a",
        )

        append_assets(
            cidr="10.40.1.0/24",
            start=20,
            count=24,
            name_prefix="k8s-payments-pod",
            role="pod",
            team="payments",
            app="payments",
            tier="container",
            asset_kind=IpMetadata.KIND_ENI,
            instance_type="k8s-pod",
            availability_zone="us-east-1a",
            extra_tags={"cluster": "payments"},
            extra_attributes={"runtime": "kubernetes"},
        )
        append_assets(
            cidr="10.40.2.0/24",
            start=20,
            count=18,
            name_prefix="k8s-observability-pod",
            role="pod",
            team="observability",
            app="observability",
            tier="container",
            asset_kind=IpMetadata.KIND_ENI,
            instance_type="k8s-pod",
            availability_zone="us-east-1b",
            extra_tags={"cluster": "observability"},
            extra_attributes={"runtime": "kubernetes"},
        )
        append_assets(
            cidr="10.40.3.0/24",
            start=20,
            count=16,
            name_prefix="k8s-analytics-pod",
            role="pod",
            team="analytics",
            app="analytics",
            tier="container",
            asset_kind=IpMetadata.KIND_ENI,
            instance_type="k8s-pod",
            availability_zone="us-east-1c",
            extra_tags={"cluster": "analytics"},
            extra_attributes={"runtime": "kubernetes"},
        )

        append_assets(
            cidr="192.168.10.0/24",
            start=30,
            count=10,
            name_prefix="corp-user",
            role="corp_client",
            team="corporate",
            app="workstation",
            tier="external",
            asset_kind=IpMetadata.KIND_ON_PREM,
            region="onprem-dc1",
            availability_zone="rack-a",
            account_owner="corp-it",
            provider="onprem",
            instance_type="desktop",
            extra_tags={"location": "hq"},
            extra_attributes={"trust_zone": "internal"},
        )
        append_assets(
            cidr="172.18.50.0/24",
            start=20,
            count=8,
            name_prefix="partner-client",
            role="partner_client",
            team="partner",
            app="partner-integration",
            tier="external",
            asset_kind=IpMetadata.KIND_ON_PREM,
            region="partner-dc",
            availability_zone="rack-p",
            account_owner="partner",
            provider="partner",
            instance_type="appliance",
            extra_tags={"partner": "northwind"},
            extra_attributes={"trust_zone": "partner"},
        )

        existing_by_ip = {item.ip_address: item for item in IpMetadata.objects.filter(ip_address__in=[r.ip_address for r in records])}
        to_create: list[IpMetadata] = []
        to_update: list[IpMetadata] = []

        for record in records:
            current = existing_by_ip.get(record.ip_address)
            if current is None:
                to_create.append(
                    IpMetadata(
                        ip_address=record.ip_address,
                        name=record.name,
                        asset_kind=record.asset_kind,
                        instance_id=record.instance_id,
                        interface_id=record.interface_id,
                        instance_type=record.instance_type,
                        state=record.state,
                        region=record.region,
                        availability_zone=record.availability_zone,
                        account_owner=record.account_owner,
                        provider=record.provider,
                        tags=record.tags,
                        attributes=record.attributes,
                    )
                )
                continue

            current.name = record.name
            current.asset_kind = record.asset_kind
            current.instance_id = record.instance_id
            current.interface_id = record.interface_id
            current.instance_type = record.instance_type
            current.state = record.state
            current.region = record.region
            current.availability_zone = record.availability_zone
            current.account_owner = record.account_owner
            current.provider = record.provider
            current.tags = record.tags
            current.attributes = record.attributes
            to_update.append(current)

        if to_create:
            IpMetadata.objects.bulk_create(to_create, batch_size=1000)
        if to_update:
            IpMetadata.objects.bulk_update(
                to_update,
                fields=[
                    "name",
                    "asset_kind",
                    "instance_id",
                    "interface_id",
                    "instance_type",
                    "state",
                    "region",
                    "availability_zone",
                    "account_owner",
                    "provider",
                    "tags",
                    "attributes",
                    "updated_at",
                ],
                batch_size=1000,
            )

        self.stdout.write(
            f"Seeded IP metadata: created={len(to_create)} updated={len(to_update)} total_seed_records={len(records)}"
        )
        return records

    def _seed_flow_logs(
        self,
        *,
        assets: list[AssetRecord],
        source: str,
        rng: random.Random,
        days: int,
        flow_pairs: int,
    ) -> int:
        now = timezone.now()
        assets_by_role: dict[str, list[AssetRecord]] = {}
        for asset in assets:
            assets_by_role.setdefault(asset.role, []).append(asset)

        all_clients = (
            assets_by_role.get("corp_client", [])
            + assets_by_role.get("partner_client", [])
            + assets_by_role.get("web", [])
            + assets_by_role.get("api", [])
            + assets_by_role.get("pod", [])
        )

        patterns = [
            FlowPattern(
                name="corp-to-web-https",
                source_role="corp_client",
                destination_role="web",
                protocol=6,
                ports=(443, 80),
                weight=18,
                accept_rate=0.995,
                response_rate=1.0,
                bytes_min=800,
                bytes_max=60_000,
                duration_min=1,
                duration_max=45,
            ),
            FlowPattern(
                name="web-to-api",
                source_role="web",
                destination_role="api",
                protocol=6,
                ports=(443, 8443, 8080),
                weight=16,
                accept_rate=0.99,
                response_rate=1.0,
                bytes_min=600,
                bytes_max=45_000,
                duration_min=1,
                duration_max=30,
            ),
            FlowPattern(
                name="api-to-db",
                source_role="api",
                destination_role="db",
                protocol=6,
                ports=(5432, 3306),
                weight=14,
                accept_rate=0.992,
                response_rate=1.0,
                bytes_min=500,
                bytes_max=120_000,
                duration_min=2,
                duration_max=90,
            ),
            FlowPattern(
                name="api-to-cache",
                source_role="api",
                destination_role="cache",
                protocol=6,
                ports=(6379,),
                weight=9,
                accept_rate=0.996,
                response_rate=1.0,
                bytes_min=300,
                bytes_max=35_000,
                duration_min=1,
                duration_max=25,
            ),
            FlowPattern(
                name="api-to-mq",
                source_role="api",
                destination_role="mq",
                protocol=6,
                ports=(5672, 15672),
                weight=7,
                accept_rate=0.98,
                response_rate=1.0,
                bytes_min=500,
                bytes_max=40_000,
                duration_min=1,
                duration_max=40,
            ),
            FlowPattern(
                name="pod-to-api",
                source_role="pod",
                destination_role="api",
                protocol=6,
                ports=(443, 8443),
                weight=10,
                accept_rate=0.985,
                response_rate=1.0,
                bytes_min=250,
                bytes_max=25_000,
                duration_min=1,
                duration_max=20,
            ),
            FlowPattern(
                name="all-to-dns",
                source_role="pod",
                destination_role="dns",
                protocol=17,
                ports=(53,),
                weight=9,
                accept_rate=0.999,
                response_rate=0.95,
                bytes_min=90,
                bytes_max=1600,
                duration_min=1,
                duration_max=8,
            ),
            FlowPattern(
                name="app-to-metrics",
                source_role="api",
                destination_role="metrics",
                protocol=17,
                ports=(8125, 4317),
                weight=8,
                accept_rate=0.99,
                response_rate=0.7,
                bytes_min=120,
                bytes_max=10_000,
                duration_min=1,
                duration_max=10,
            ),
            FlowPattern(
                name="api-to-ntp",
                source_role="api",
                destination_role="ntp",
                protocol=17,
                ports=(123,),
                weight=5,
                accept_rate=0.995,
                response_rate=0.9,
                bytes_min=64,
                bytes_max=512,
                duration_min=1,
                duration_max=5,
            ),
            FlowPattern(
                name="monitoring-icmp",
                source_role="metrics",
                destination_role="api",
                protocol=1,
                ports=(0,),
                weight=4,
                accept_rate=0.995,
                response_rate=0.8,
                bytes_min=64,
                bytes_max=1024,
                duration_min=1,
                duration_max=5,
            ),
            FlowPattern(
                name="partner-to-api",
                source_role="partner_client",
                destination_role="api",
                protocol=6,
                ports=(443,),
                weight=5,
                accept_rate=0.9,
                response_rate=1.0,
                bytes_min=400,
                bytes_max=55_000,
                duration_min=1,
                duration_max=55,
            ),
            FlowPattern(
                name="corp-to-bastion",
                source_role="corp_client",
                destination_role="edge",
                protocol=6,
                ports=(22, 3389),
                weight=4,
                accept_rate=0.8,
                response_rate=1.0,
                bytes_min=200,
                bytes_max=20_000,
                duration_min=1,
                duration_max=120,
            ),
        ]

        if not all_clients:
            raise RuntimeError("No client asset pool available for flow generation.")

        pattern_weights = [pattern.weight for pattern in patterns]
        entries: list[FlowLogEntry] = []

        for _ in range(flow_pairs):
            pattern = rng.choices(patterns, weights=pattern_weights, k=1)[0]
            source_pool = assets_by_role.get(pattern.source_role, [])
            destination_pool = assets_by_role.get(pattern.destination_role, [])
            if not source_pool or not destination_pool:
                continue

            source_asset = rng.choice(source_pool)
            destination_asset = rng.choice(destination_pool)
            if source_asset.ip_address == destination_asset.ip_address:
                continue

            protocol = pattern.protocol
            destination_port = 0 if protocol == 1 else rng.choice(pattern.ports)
            source_port = 0 if protocol == 1 else rng.randint(1024, 65535)
            action = "ACCEPT" if rng.random() <= pattern.accept_rate else "REJECT"
            span_seconds = max(1, days * 24 * 60 * 60)
            start_offset = rng.randint(0, span_seconds)
            duration_seconds = rng.randint(pattern.duration_min, pattern.duration_max)
            start_time = now - timedelta(seconds=start_offset)
            end_time = start_time + timedelta(seconds=duration_seconds)

            c2s_bytes = rng.randint(pattern.bytes_min, pattern.bytes_max)
            c2s_packets = max(1, c2s_bytes // rng.randint(90, 1400))

            entries.append(
                FlowLogEntry(
                    version=2,
                    account_id=source_asset.account_owner[:32],
                    interface_id=source_asset.interface_id[:32],
                    srcaddr=source_asset.ip_address,
                    dstaddr=destination_asset.ip_address,
                    srcport=source_port,
                    dstport=destination_port,
                    protocol=protocol,
                    packets=c2s_packets,
                    bytes=c2s_bytes,
                    start_time=start_time,
                    end_time=end_time,
                    action=action,
                    log_status="OK",
                    source=source,
                    raw_line=f"demo|{pattern.name}|c2s",
                )
            )

            should_create_response = action == "ACCEPT" and rng.random() <= pattern.response_rate
            if should_create_response:
                s2c_bytes = max(64, int(c2s_bytes * rng.uniform(0.35, 0.95)))
                s2c_packets = max(1, s2c_bytes // rng.randint(90, 1300))
                response_duration = rng.randint(1, max(1, duration_seconds))

                entries.append(
                    FlowLogEntry(
                        version=2,
                        account_id=destination_asset.account_owner[:32],
                        interface_id=destination_asset.interface_id[:32],
                        srcaddr=destination_asset.ip_address,
                        dstaddr=source_asset.ip_address,
                        srcport=destination_port,
                        dstport=source_port,
                        protocol=protocol,
                        packets=s2c_packets,
                        bytes=s2c_bytes,
                        start_time=start_time + timedelta(seconds=1),
                        end_time=start_time + timedelta(seconds=response_duration),
                        action=action,
                        log_status="OK",
                        source=source,
                        raw_line=f"demo|{pattern.name}|s2c",
                    )
                )

        # Force a high-volume multi-port host pair to exercise edge aggregation UI paths.
        multi_port_sources = assets_by_role.get("api", [])
        multi_port_targets = assets_by_role.get("db", [])
        if multi_port_sources and multi_port_targets:
            source_asset = multi_port_sources[0]
            destination_asset = multi_port_targets[0]
            for port in (5432, 3306, 8080, 8443, 1521):
                for _ in range(20):
                    source_port = rng.randint(20000, 65000)
                    start_time = now - timedelta(seconds=rng.randint(0, days * 24 * 60 * 60))
                    end_time = start_time + timedelta(seconds=rng.randint(1, 25))
                    bytes_sent = rng.randint(500, 50_000)
                    packets_sent = max(1, bytes_sent // rng.randint(120, 1200))

                    entries.append(
                        FlowLogEntry(
                            version=2,
                            account_id=source_asset.account_owner[:32],
                            interface_id=source_asset.interface_id[:32],
                            srcaddr=source_asset.ip_address,
                            dstaddr=destination_asset.ip_address,
                            srcport=source_port,
                            dstport=port,
                            protocol=6,
                            packets=packets_sent,
                            bytes=bytes_sent,
                            start_time=start_time,
                            end_time=end_time,
                            action="ACCEPT",
                            log_status="OK",
                            source=source,
                            raw_line="demo|multi-port-stress|c2s",
                        )
                    )
                    entries.append(
                        FlowLogEntry(
                            version=2,
                            account_id=destination_asset.account_owner[:32],
                            interface_id=destination_asset.interface_id[:32],
                            srcaddr=destination_asset.ip_address,
                            dstaddr=source_asset.ip_address,
                            srcport=port,
                            dstport=source_port,
                            protocol=6,
                            packets=max(1, packets_sent // 2),
                            bytes=max(64, int(bytes_sent * 0.65)),
                            start_time=start_time + timedelta(seconds=1),
                            end_time=end_time,
                            action="ACCEPT",
                            log_status="OK",
                            source=source,
                            raw_line="demo|multi-port-stress|s2c",
                        )
                    )

        if entries:
            FlowLogEntry.objects.bulk_create(entries, batch_size=1000)
        self.stdout.write(f"Seeded flow log entries for source '{source}': {len(entries)}")
        return len(entries)

    def _seed_firewall_snapshot_groups(
        self,
        groups: dict[str, NetworkGroup],
        assets: list[AssetRecord],
    ) -> int:
        created_or_updated = 0

        payments_container_group = groups.get("k8s-payments-pods")
        observability_container_group = groups.get("k8s-observability-pods")
        if not payments_container_group or not observability_container_group:
            self.stdout.write("Skipped snapshot generation: required container groups are missing.")
            return created_or_updated

        payments_group_cidrs = payments_container_group.cidr_values
        tag_snapshot_cidrs = sorted(
            {
                _host_cidr(asset.ip_address)
                for asset in assets
                if asset.tags.get("app") == "payments"
                and asset.tags.get("tier") == "container"
                and _in_any_network(asset.ip_address, payments_group_cidrs)
            }
        )

        tag_source_meta = {
            "mode": "tag",
            "tagKey": "app",
            "tagValue": "payments",
            "containerGroupId": str(payments_container_group.id),
            "syncedAt": timezone.now().isoformat(),
        }
        tag_snapshot_group, _ = NetworkGroup.objects.update_or_create(
            name="sim-tag-payments-pods",
            defaults={
                "kind": NetworkGroup.KIND_CUSTOM,
                "cidrs": tag_snapshot_cidrs[:120],
                "cidr": tag_snapshot_cidrs[0] if tag_snapshot_cidrs else payments_group_cidrs[0],
                "tags": [SIMULATOR_TAG],
                "description": _make_snapshot_description(
                    "Demo tag snapshot for payments pods.",
                    tag_source_meta,
                ),
            },
        )
        created_or_updated += 1

        container_source_meta = {
            "mode": "container",
            "containerGroupIds": [
                str(payments_container_group.id),
                str(observability_container_group.id),
            ],
            "syncedAt": timezone.now().isoformat(),
        }
        container_snapshot_cidrs = sorted(
            set(payments_container_group.cidr_values + observability_container_group.cidr_values)
        )
        NetworkGroup.objects.update_or_create(
            name="sim-container-platform",
            defaults={
                "kind": NetworkGroup.KIND_CUSTOM,
                "cidrs": container_snapshot_cidrs,
                "cidr": container_snapshot_cidrs[0],
                "tags": [SIMULATOR_TAG],
                "description": _make_snapshot_description(
                    "Demo container snapshot for platform runtime.",
                    container_source_meta,
                ),
            },
        )
        created_or_updated += 1

        self.stdout.write(
            f"Seeded firewall simulator snapshots: {created_or_updated} "
            f"(example tag snapshot id={tag_snapshot_group.id})"
        )
        return created_or_updated
