import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ipaddr from "ipaddr.js";
import { api, extractResults } from "../lib/api";
import { formatBytes, formatInt } from "../lib/graph";
import Icon from "../components/Icon";

const SIMULATOR_RULES_STORAGE_KEY = "firewall-simulator-rules-v1";
const SOURCE_META_PREFIX = "[FIREWALL_SIM_SOURCE]";
const PAGE_SIZE = 1000;
const RULESET_EXPORT_VERSION = 1;

const PROTOCOL_NAMES = {
  1: "ICMP",
  4: "IPIP",
  6: "TCP",
  17: "UDP",
};

const RULE_PROTOCOL_OPTIONS = [
  { value: "ANY", label: "Any Protocol" },
  { value: "6", label: "TCP (6)" },
  { value: "17", label: "UDP (17)" },
  { value: "1", label: "ICMP (1, port 0)" },
  { value: "4", label: "IP-in-IP (4)" },
];

const EMPTY_RULE_FORM = {
  name: "",
  sourceType: "ANY",
  sourceValue: "",
  sourceGroupId: "",
  destinationType: "ANY",
  destinationValue: "",
  destinationGroupId: "",
  protocol: "ANY",
  destinationPort: "",
};

const EMPTY_GROUP_FORM = {
  name: "",
  description: "",
  staticCidrs: "",
  tagKey: "",
  tagValue: "",
  tagContainerGroupId: "",
  containerSourceGroupIds: [],
};

function makeId(prefix = "id") {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;
}

function normalizeTagMap(value) {
  if (!value) return {};
  if (typeof value === "object" && !Array.isArray(value)) {
    const payload = {};
    Object.entries(value).forEach(([key, tagValue]) => {
      const normalizedKey = String(key || "").trim();
      if (!normalizedKey) return;
      payload[normalizedKey] = tagValue == null ? "" : String(tagValue).trim();
    });
    return payload;
  }

  if (Array.isArray(value)) {
    const payload = {};
    value.forEach((item) => {
      const text = String(item || "").trim();
      if (!text) return;
      if (text.includes("=")) {
        const [key, ...rest] = text.split("=");
        const normalizedKey = key.trim();
        if (!normalizedKey) return;
        payload[normalizedKey] = rest.join("=").trim();
      } else {
        payload[text] = "";
      }
    });
    return payload;
  }

  return {};
}

function ipToHostCidr(ipText) {
  const parsed = ipaddr.parse(ipText);
  const suffix = parsed.kind() === "ipv6" ? 128 : 32;
  return `${ipText}/${suffix}`;
}

function parseNetwork(value) {
  const text = String(value || "").trim();
  if (!text) {
    throw new Error("Address value cannot be empty.");
  }

  if (text.includes("/")) {
    return ipaddr.parseCIDR(text);
  }

  const parsed = ipaddr.parse(text);
  const bits = parsed.kind() === "ipv6" ? 128 : 32;
  return [parsed, bits];
}

function networkToText(tuple) {
  const [range, bits] = tuple;
  const rangeText = typeof range.toNormalizedString === "function"
    ? range.toNormalizedString()
    : range.toString();
  return `${rangeText}/${bits}`;
}

function getGroupCidrs(group) {
  if (!group) return [];
  if (Array.isArray(group.cidrs) && group.cidrs.length > 0) {
    return group.cidrs;
  }
  if (group.cidr) {
    return [group.cidr];
  }
  return [];
}

function parseCidrList(value) {
  const unique = new Set();
  String(value || "")
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
    .forEach((cidr) => {
      const network = parseNetwork(cidr);
      unique.add(networkToText(network));
    });

  return [...unique];
}

function parseGroupSourceMeta(description) {
  const lines = String(description || "").split(/\r?\n/);
  const bodyLines = [];
  let sourceMeta = null;

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith(SOURCE_META_PREFIX)) {
      bodyLines.push(line);
      return;
    }

    const jsonText = trimmed.slice(SOURCE_META_PREFIX.length).trim();
    if (!jsonText) return;
    try {
      sourceMeta = JSON.parse(jsonText);
    } catch {
      sourceMeta = null;
    }
  });

  return {
    sourceMeta,
    description: bodyLines.join("\n").trim(),
  };
}

function buildDescriptionWithSourceMeta(description, sourceMeta) {
  const body = String(description || "").trim();
  if (!sourceMeta) return body;
  const marker = `${SOURCE_META_PREFIX} ${JSON.stringify(sourceMeta)}`;
  return body ? `${body}\n${marker}` : marker;
}

function matchesNetworks(ipInput, networks) {
  if (!ipInput || !Array.isArray(networks) || networks.length === 0) return false;

  try {
    const parsedIp = typeof ipInput === "string" ? ipaddr.parse(ipInput) : ipInput;
    return networks.some(([range, bits]) => {
      try {
        return parsedIp.match(range, bits);
      } catch {
        return false;
      }
    });
  } catch {
    return false;
  }
}

async function listAllPages(listFn, options = {}) {
  const onProgress = typeof options.onProgress === "function" ? options.onProgress : null;
  let page = 1;
  const items = [];

  for (;;) {
    const response = await listFn({ page, page_size: PAGE_SIZE });
    const chunk = extractResults(response);
    items.push(...chunk);
    const totalCount = Number(response?.count || 0);
    if (onProgress) {
      const percent = totalCount > 0
        ? Math.min(100, Math.round((items.length / totalCount) * 100))
        : 0;
      onProgress({
        loaded: items.length,
        total: totalCount,
        percent,
      });
    }

    if (!Array.isArray(response?.results)) {
      break;
    }

    if (totalCount > 0 && items.length >= totalCount) {
      break;
    }

    if (chunk.length < PAGE_SIZE) {
      break;
    }

    page += 1;
  }

  return items;
}

function formatSourceMeta(meta, groupsById) {
  if (!meta || typeof meta !== "object") return "";

  if (meta.mode === "tag") {
    const tag = meta.tagValue
      ? `${meta.tagKey}=${meta.tagValue}`
      : meta.tagKey;

    if (meta.containerGroupId) {
      const group = groupsById.get(String(meta.containerGroupId));
      const label = group?.name || `Group ${meta.containerGroupId}`;
      return `Tag snapshot (${tag}) within ${label}`;
    }

    return `Tag snapshot (${tag})`;
  }

  if (meta.mode === "container") {
    const groupIds = Array.isArray(meta.containerGroupIds)
      ? meta.containerGroupIds
      : meta.containerGroupId
        ? [meta.containerGroupId]
        : [];
    if (groupIds.length === 0) {
      return "Container snapshot";
    }

    const labels = groupIds
      .map((groupId) => {
        const group = groupsById.get(String(groupId));
        return group?.name || `Group ${groupId}`;
      })
      .slice(0, 2);

    if (groupIds.length <= 2) {
      return `Container snapshot (${labels.join(", ")})`;
    }
    return `Container snapshot (${labels.join(", ")} +${groupIds.length - 2})`;
  }

  return "";
}

function formatRuleProtocol(protocolValue) {
  if (!protocolValue || protocolValue === "ANY") {
    return "Any";
  }
  const protocolNumber = Number(protocolValue);
  return PROTOCOL_NAMES[protocolNumber] || `Protocol ${protocolValue}`;
}

function formatRuleDestinationPort(rule) {
  const protocolValue = String(rule?.protocol || "ANY");
  if (protocolValue === "1") {
    return "0";
  }
  const portValue = String(rule?.destinationPort || "").trim();
  return portValue || "Any";
}

function createRuleMatcher(rule, groupNetworksById) {
  function buildAddressMatcher(type, value, groupId) {
    if (type === "ANY") {
      return () => true;
    }

    if (type === "GROUP") {
      const networks = groupNetworksById.get(String(groupId)) || [];
      return (ipObj) => matchesNetworks(ipObj, networks);
    }

    if (type === "IP_CIDR") {
      try {
        const network = parseNetwork(value);
        return (ipObj) => matchesNetworks(ipObj, [network]);
      } catch {
        return () => false;
      }
    }

    return () => false;
  }

  const sourceMatches = buildAddressMatcher(
    rule.sourceType,
    rule.sourceValue,
    rule.sourceGroupId,
  );
  const destinationMatches = buildAddressMatcher(
    rule.destinationType,
    rule.destinationValue,
    rule.destinationGroupId,
  );

  let destinationPort = null;
  if (String(rule.destinationPort || "").trim()) {
    const parsed = Number(rule.destinationPort);
    if (Number.isInteger(parsed) && parsed >= 0) {
      destinationPort = parsed;
    }
  }

  let protocol = null;
  if (String(rule.protocol || "").trim() && rule.protocol !== "ANY") {
    const parsed = Number(rule.protocol);
    if (Number.isInteger(parsed) && parsed > 0) {
      protocol = parsed;
    }
  }
  if (protocol === 1 && destinationPort == null) {
    destinationPort = 0;
  }

  return (flow) => {
    if (!sourceMatches(flow._parsedClientIp || flow.client_ip)) return false;
    if (!destinationMatches(flow._parsedServerIp || flow.server_ip)) return false;
    if (protocol != null && Number(flow.protocol) !== protocol) return false;

    if (destinationPort != null) {
      return Number(flow.server_port) === destinationPort;
    }

    return true;
  };
}

function resolveSnapshotCidrs(sourceMeta, metadata, groupNetworksById, groupsById) {
  if (!sourceMeta || typeof sourceMeta !== "object") return [];

  if (sourceMeta.mode === "container") {
    const groupIds = Array.isArray(sourceMeta.containerGroupIds)
      ? sourceMeta.containerGroupIds
      : sourceMeta.containerGroupId
        ? [sourceMeta.containerGroupId]
        : [];

    const cidrLines = [];
    groupIds.forEach((groupId) => {
      const group = groupsById.get(String(groupId));
      if (!group) return;
      cidrLines.push(...getGroupCidrs(group));
    });

    if (cidrLines.length === 0) return [];
    return parseCidrList(cidrLines.join("\n"));
  }

  if (sourceMeta.mode === "tag") {
    const tagKey = String(sourceMeta.tagKey || "").trim().toLowerCase();
    const tagValue = String(sourceMeta.tagValue || "").trim().toLowerCase();
    if (!tagKey) return [];

    const containerId = String(sourceMeta.containerGroupId || "").trim();
    const containerNetworks = containerId ? (groupNetworksById.get(containerId) || []) : [];

    const unique = new Set();

    metadata.forEach((asset) => {
      const ipAddress = String(asset.ip_address || "").trim();
      if (!ipAddress) return;

      if (containerId && !matchesNetworks(ipAddress, containerNetworks)) {
        return;
      }

      const tags = normalizeTagMap(asset.tags);
      const matchedTag = Object.entries(tags).some(([key, value]) => {
        if (String(key || "").trim().toLowerCase() !== tagKey) {
          return false;
        }

        if (!tagValue) {
          return true;
        }

        return String(value || "").trim().toLowerCase() === tagValue;
      });

      if (!matchedTag) return;

      try {
        unique.add(ipToHostCidr(ipAddress));
      } catch {
        // Skip invalid IPs.
      }
    });

    return [...unique];
  }

  return [];
}

function hydrateStoredRules(value) {
  if (!Array.isArray(value)) return [];

  return value
    .map((rule, index) => {
      const normalizedProtocol = ["ANY", "1", "6", "17"].includes(String(rule.protocol || "ANY"))
        ? String(rule.protocol || "ANY")
        : "ANY";
      let normalizedPort = String(rule.destinationPort || "").trim();
      if (normalizedProtocol === "1" && normalizedPort === "") {
        normalizedPort = "0";
      }

      return {
      id: rule.id || makeId(`rule${index + 1}`),
      name: String(rule.name || "").trim(),
      sourceType: ["ANY", "IP_CIDR", "GROUP"].includes(rule.sourceType)
        ? rule.sourceType
        : "ANY",
      sourceValue: String(rule.sourceValue || "").trim(),
      sourceGroupId: String(rule.sourceGroupId || ""),
      destinationType: ["ANY", "IP_CIDR", "GROUP"].includes(rule.destinationType)
        ? rule.destinationType
        : "ANY",
      destinationValue: String(rule.destinationValue || "").trim(),
      destinationGroupId: String(rule.destinationGroupId || ""),
      protocol: normalizedProtocol,
      destinationPort: normalizedPort,
      };
    })
    .filter((rule) => rule.id);
}

function normalizeImportedRulesPayload(payload) {
  if (Array.isArray(payload)) {
    return payload;
  }

  if (payload && typeof payload === "object" && Array.isArray(payload.rules)) {
    return payload.rules;
  }

  throw new Error("Ruleset JSON must be an array of rules or an object with a `rules` array.");
}

function validateImportedRules(rules) {
  rules.forEach((rule, index) => {
    const ruleLabel = rule.name || `Rule ${index + 1}`;
    const protocolValue = String(rule.protocol || "ANY");
    const destinationPort = String(rule.destinationPort || "").trim();

    if (rule.sourceType === "IP_CIDR") {
      if (!rule.sourceValue) {
        throw new Error(`${ruleLabel}: source IP/CIDR is required.`);
      }
      try {
        parseNetwork(rule.sourceValue);
      } catch (err) {
        throw new Error(`${ruleLabel}: source address is invalid (${err.message}).`);
      }
    }

    if (rule.sourceType === "GROUP" && !rule.sourceGroupId) {
      throw new Error(`${ruleLabel}: source group is required.`);
    }

    if (rule.destinationType === "IP_CIDR") {
      if (!rule.destinationValue) {
        throw new Error(`${ruleLabel}: destination IP/CIDR is required.`);
      }
      try {
        parseNetwork(rule.destinationValue);
      } catch (err) {
        throw new Error(`${ruleLabel}: destination address is invalid (${err.message}).`);
      }
    }

    if (rule.destinationType === "GROUP" && !rule.destinationGroupId) {
      throw new Error(`${ruleLabel}: destination group is required.`);
    }

    if (!["ANY", "1", "6", "17"].includes(protocolValue)) {
      throw new Error(`${ruleLabel}: protocol must be Any, ICMP (1), TCP (6), or UDP (17).`);
    }

    if (protocolValue === "1") {
      if (destinationPort && destinationPort !== "0") {
        throw new Error(`${ruleLabel}: ICMP destination port must be 0.`);
      }
      return;
    }

    if (destinationPort) {
      const port = Number(destinationPort);
      if (!Number.isInteger(port) || port <= 0 || port > 65535) {
        throw new Error(`${ruleLabel}: destination port must be between 1 and 65535.`);
      }
    }
  });
}

function buildRulesetExportPayload(rules) {
  return {
    version: RULESET_EXPORT_VERSION,
    exported_at: new Date().toISOString(),
    rule_count: rules.length,
    rules: rules.map((rule) => ({
      id: String(rule.id || ""),
      name: String(rule.name || "").trim(),
      sourceType: String(rule.sourceType || "ANY"),
      sourceValue: String(rule.sourceValue || "").trim(),
      sourceGroupId: String(rule.sourceGroupId || ""),
      destinationType: String(rule.destinationType || "ANY"),
      destinationValue: String(rule.destinationValue || "").trim(),
      destinationGroupId: String(rule.destinationGroupId || ""),
      protocol: String(rule.protocol || "ANY"),
      destinationPort: String(rule.destinationPort || "").trim(),
    })),
  };
}

export default function FirewallSimulatorPage() {
  const [loading, setLoading] = useState(true);
  const [busyKey, setBusyKey] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [flowFetchProgress, setFlowFetchProgress] = useState({
    loaded: 0,
    total: 0,
    percent: 0,
  });

  const [correlatedFlows, setCorrelatedFlows] = useState([]);
  const [metadata, setMetadata] = useState([]);
  const [groups, setGroups] = useState([]);

  const [rules, setRules] = useState([]);
  const [ruleForm, setRuleForm] = useState(EMPTY_RULE_FORM);
  const [ruleFormError, setRuleFormError] = useState("");

  const [groupMode, setGroupMode] = useState("static");
  const [groupForm, setGroupForm] = useState(EMPTY_GROUP_FORM);
  const [groupFormError, setGroupFormError] = useState("");

  const [showUnmatchedOnly, setShowUnmatchedOnly] = useState(false);
  const importRulesInputRef = useRef(null);

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(SIMULATOR_RULES_STORAGE_KEY);
      if (!raw) {
        return;
      }
      const parsed = JSON.parse(raw);
      setRules(hydrateStoredRules(parsed));
    } catch {
      setRules([]);
    }
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(SIMULATOR_RULES_STORAGE_KEY, JSON.stringify(rules));
    } catch {
      // Ignore localStorage errors.
    }
  }, [rules]);

  useEffect(() => {
    setRuleForm((prev) => {
      const protocolValue = String(prev.protocol || "ANY");
      if (protocolValue === "1" && prev.destinationPort !== "0") {
        return { ...prev, destinationPort: "0" };
      }
      if (protocolValue !== "1" && prev.destinationPort === "0") {
        return { ...prev, destinationPort: "" };
      }
      return prev;
    });
  }, [ruleForm.protocol]);

  const refreshData = useCallback(async () => {
    setLoading(true);
    setError("");
    setFlowFetchProgress({ loaded: 0, total: 0, percent: 0 });

    try {
      const [flows, assets, networkGroups] = await Promise.all([
        listAllPages(
          (params) => api.listCorrelatedFlows(params),
          {
            onProgress: (progress) => {
              setFlowFetchProgress(progress);
            },
          },
        ),
        listAllPages((params) => api.listIpMetadata(params)),
        listAllPages((params) => api.listNetworkGroups(params)),
      ]);

      const enrichedFlows = flows.map((flow) => {
        let _parsedClientIp = null;
        try { _parsedClientIp = ipaddr.parse(flow.client_ip); } catch (e) {}

        let _parsedServerIp = null;
        try { _parsedServerIp = ipaddr.parse(flow.server_ip); } catch (e) {}

        return {
          ...flow,
          _parsedClientIp,
          _parsedServerIp,
          _lastSeenMs: new Date(flow.last_seen).getTime(),
        };
      });

      setCorrelatedFlows(
        enrichedFlows.sort((a, b) => b._lastSeenMs - a._lastSeenMs)
      );
      setFlowFetchProgress({
        loaded: flows.length,
        total: flows.length,
        percent: 100,
      });
      setMetadata(assets);
      setGroups(networkGroups);
    } catch (err) {
      setError(err.message || "Failed to load simulator data");
      setCorrelatedFlows([]);
      setMetadata([]);
      setGroups([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshData();
  }, [refreshData]);

  const groupsById = useMemo(() => {
    const map = new Map();
    groups.forEach((group) => {
      map.set(String(group.id), group);
    });
    return map;
  }, [groups]);

  const groupNetworksById = useMemo(() => {
    const map = new Map();
    groups.forEach((group) => {
      const parsedNetworks = [];
      getGroupCidrs(group).forEach((cidr) => {
        try {
          parsedNetworks.push(parseNetwork(cidr));
        } catch {
          // Skip invalid CIDRs.
        }
      });
      map.set(String(group.id), parsedNetworks);
    });
    return map;
  }, [groups]);

  const compiledRules = useMemo(
    () => rules.map((rule) => ({ ...rule, matcher: createRuleMatcher(rule, groupNetworksById) })),
    [rules, groupNetworksById],
  );

  const simulation = useMemo(() => {
    const ruleStats = rules.map(() => ({
      matchedFlows: 0,
      matchedSessions: 0,
      matchedBytes: 0,
    }));

    let unmatchedFlowCount = 0;
    let matchedFlowCount = 0;

    const rows = correlatedFlows.map((flow) => {
      const totalBytes = Number(flow.c2s_bytes || 0) + Number(flow.s2c_bytes || 0);
      const sessionCount = Number(flow.flow_count || 0);

      let matchedRuleIndex = -1;
      for (let index = 0; index < compiledRules.length; index += 1) {
        if (compiledRules[index].matcher(flow)) {
          matchedRuleIndex = index;
          break;
        }
      }

      if (matchedRuleIndex >= 0) {
        matchedFlowCount += 1;
        ruleStats[matchedRuleIndex].matchedFlows += 1;
        ruleStats[matchedRuleIndex].matchedSessions += sessionCount;
        ruleStats[matchedRuleIndex].matchedBytes += totalBytes;
      } else {
        unmatchedFlowCount += 1;
      }

      return {
        ...flow,
        totalBytes,
        sessionCount,
        matchedRuleIndex,
      };
    });

    return {
      rows,
      ruleStats,
      matchedFlowCount,
      unmatchedFlowCount,
      totalFlows: rows.length,
    };
  }, [correlatedFlows, compiledRules, rules]);

  const displayedRows = useMemo(() => {
    if (!showUnmatchedOnly) {
      return simulation.rows;
    }
    return simulation.rows.filter((row) => row.matchedRuleIndex < 0);
  }, [simulation.rows, showUnmatchedOnly]);

  const dynamicGroups = useMemo(
    () => groups
      .map((group) => {
        const parsed = parseGroupSourceMeta(group.description);
        return {
          group,
          description: parsed.description,
          sourceMeta: parsed.sourceMeta,
        };
      })
      .filter((item) => item.sourceMeta),
    [groups],
  );

  const containerGroups = useMemo(
    () => groups.filter((group) => (group.kind || "").toUpperCase() === "CONTAINER"),
    [groups],
  );
  const hasContainerGroups = containerGroups.length > 0;
  const containerSourceGroups = hasContainerGroups ? containerGroups : groups;

  function resetGroupForm() {
    setGroupForm(EMPTY_GROUP_FORM);
    setGroupFormError("");
  }

  function updateRuleForm(field, value) {
    setRuleForm((prev) => ({ ...prev, [field]: value }));
    setRuleFormError("");
  }

  function updateGroupForm(field, value) {
    setGroupForm((prev) => ({ ...prev, [field]: value }));
    setGroupFormError("");
  }

  function toggleContainerSourceGroup(groupId) {
    const idText = String(groupId);
    setGroupForm((prev) => {
      const selectedIds = Array.isArray(prev.containerSourceGroupIds)
        ? prev.containerSourceGroupIds
        : [];
      const isSelected = selectedIds.includes(idText);
      return {
        ...prev,
        containerSourceGroupIds: isSelected
          ? selectedIds.filter((item) => item !== idText)
          : [...selectedIds, idText],
      };
    });
    setGroupFormError("");
  }

  function selectAllContainerSourceGroups() {
    setGroupForm((prev) => ({
      ...prev,
      containerSourceGroupIds: containerSourceGroups.map((group) => String(group.id)),
    }));
    setGroupFormError("");
  }

  function clearContainerSourceGroups() {
    setGroupForm((prev) => ({
      ...prev,
      containerSourceGroupIds: [],
    }));
    setGroupFormError("");
  }

  function handleAddRule(event) {
    event.preventDefault();
    setRuleFormError("");

    if (ruleForm.sourceType === "IP_CIDR") {
      try {
        parseNetwork(ruleForm.sourceValue);
      } catch (err) {
        setRuleFormError(`Source address is invalid: ${err.message}`);
        return;
      }
    }

    if (ruleForm.sourceType === "GROUP" && !ruleForm.sourceGroupId) {
      setRuleFormError("Select a source address group.");
      return;
    }

    if (ruleForm.destinationType === "IP_CIDR") {
      try {
        parseNetwork(ruleForm.destinationValue);
      } catch (err) {
        setRuleFormError(`Destination address is invalid: ${err.message}`);
        return;
      }
    }

    if (ruleForm.destinationType === "GROUP" && !ruleForm.destinationGroupId) {
      setRuleFormError("Select a destination address group.");
      return;
    }

    if (!["ANY", "1", "6", "17"].includes(String(ruleForm.protocol || "ANY"))) {
      setRuleFormError("Protocol must be Any, TCP, UDP, or ICMP.");
      return;
    }

    const normalizedProtocol = String(ruleForm.protocol || "ANY");
    let normalizedPort = String(ruleForm.destinationPort || "").trim();

    if (normalizedProtocol === "1") {
      if (!normalizedPort) {
        normalizedPort = "0";
      }
      if (normalizedPort !== "0") {
        setRuleFormError("For ICMP, destination port must be 0.");
        return;
      }
    } else if (normalizedPort) {
      const parsedPort = Number(normalizedPort);
      if (!Number.isInteger(parsedPort) || parsedPort <= 0 || parsedPort > 65535) {
        setRuleFormError("Destination port must be between 1 and 65535.");
        return;
      }
    }

    const nextRule = {
      id: makeId("rule"),
      name: ruleForm.name.trim(),
      sourceType: ruleForm.sourceType,
      sourceValue: ruleForm.sourceValue.trim(),
      sourceGroupId: String(ruleForm.sourceGroupId || ""),
      destinationType: ruleForm.destinationType,
      destinationValue: ruleForm.destinationValue.trim(),
      destinationGroupId: String(ruleForm.destinationGroupId || ""),
      protocol: normalizedProtocol,
      destinationPort: normalizedPort,
    };

    setRules((prev) => [...prev, nextRule]);
    setRuleForm(EMPTY_RULE_FORM);
  }

  function deleteRule(ruleId) {
    setRules((prev) => prev.filter((rule) => rule.id !== ruleId));
  }

  function moveRule(ruleId, direction) {
    setRules((prev) => {
      const index = prev.findIndex((rule) => rule.id === ruleId);
      if (index < 0) return prev;
      const nextIndex = index + direction;
      if (nextIndex < 0 || nextIndex >= prev.length) return prev;

      const copy = [...prev];
      const [item] = copy.splice(index, 1);
      copy.splice(nextIndex, 0, item);
      return copy;
    });
  }

  function clearRules() {
    setRules([]);
    setRuleFormError("");
  }

  function handleExportRules() {
    setError("");
    setSuccess("");
    try {
      const payload = buildRulesetExportPayload(rules);
      const jsonText = JSON.stringify(payload, null, 2);
      const blob = new Blob([jsonText], { type: "application/json" });
      const objectUrl = window.URL.createObjectURL(blob);
      const timestamp = new Date().toISOString().replaceAll(":", "-").split(".")[0];
      const anchor = window.document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `firewall-ruleset-${timestamp}.json`;
      window.document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(objectUrl);
      setSuccess(`Exported ${formatInt(rules.length)} rule${rules.length === 1 ? "" : "s"} to JSON.`);
    } catch (err) {
      setError(err.message || "Failed to export ruleset JSON.");
    }
  }

  async function handleImportRulesFile(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    setError("");
    setSuccess("");
    setRuleFormError("");

    try {
      const fileText = await file.text();
      let parsed;
      try {
        parsed = JSON.parse(fileText);
      } catch {
        throw new Error("Selected file is not valid JSON.");
      }

      const incomingRules = normalizeImportedRulesPayload(parsed);
      const hydratedRules = hydrateStoredRules(incomingRules);
      validateImportedRules(hydratedRules);

      setRules(hydratedRules);
      setSuccess(
        `Imported ${formatInt(hydratedRules.length)} rule${hydratedRules.length === 1 ? "" : "s"} from ${file.name}.`,
      );
    } catch (err) {
      setError(err.message || "Failed to import ruleset JSON.");
    }
  }

  async function handleSaveGroup(event) {
    event.preventDefault();
    setGroupFormError("");
    setSuccess("");
    setError("");

    const name = groupForm.name.trim();
    if (!name) {
      setGroupFormError("Group name is required.");
      return;
    }

    let cidrs = [];
    let sourceMeta = null;

    try {
      if (groupMode === "static") {
        cidrs = parseCidrList(groupForm.staticCidrs);
        if (cidrs.length === 0) {
          setGroupFormError("Provide at least one CIDR or IP for the static group.");
          return;
        }
      }

      if (groupMode === "tag") {
        const tagKey = groupForm.tagKey.trim();
        const tagValue = groupForm.tagValue.trim();

        if (!tagKey) {
          setGroupFormError("Tag key is required for tag-based snapshots.");
          return;
        }

        sourceMeta = {
          mode: "tag",
          tagKey,
          tagValue,
          containerGroupId: groupForm.tagContainerGroupId || null,
          syncedAt: new Date().toISOString(),
        };

        cidrs = resolveSnapshotCidrs(sourceMeta, metadata, groupNetworksById, groupsById);
        if (cidrs.length === 0) {
          setGroupFormError("Tag snapshot did not return any IPs.");
          return;
        }
      }

      if (groupMode === "container") {
        const selectedContainerGroupIds = Array.isArray(groupForm.containerSourceGroupIds)
          ? groupForm.containerSourceGroupIds
          : [];

        if (selectedContainerGroupIds.length === 0) {
          setGroupFormError("Select one or more source groups for container snapshot mode.");
          return;
        }

        sourceMeta = {
          mode: "container",
          containerGroupIds: selectedContainerGroupIds,
          syncedAt: new Date().toISOString(),
        };

        cidrs = resolveSnapshotCidrs(sourceMeta, metadata, groupNetworksById, groupsById);
        if (cidrs.length === 0) {
          setGroupFormError("Container snapshot did not return any CIDRs.");
          return;
        }
      }
    } catch (err) {
      setGroupFormError(err.message || "Failed to resolve group CIDRs");
      return;
    }

    const existingByName = groups.find((group) => group.name === name);
    if (existingByName) {
      const existingMeta = parseGroupSourceMeta(existingByName.description).sourceMeta;
      if (!existingMeta) {
        setGroupFormError(
          `A network group named "${name}" already exists and is not simulator-managed. Use a different name.`,
        );
        return;
      }
    }

    const description = buildDescriptionWithSourceMeta(groupForm.description, sourceMeta);
    const existingTags = Array.isArray(existingByName?.tags) ? existingByName.tags : [];
    const payload = {
      name,
      kind: existingByName?.kind || "CUSTOM",
      cidrs,
      description,
      tags: [...new Set([...existingTags, "firewall-simulator"])],
    };

    setBusyKey("save-group");
    try {
      if (existingByName) {
        await api.updateNetworkGroup(existingByName.id, payload);
        setSuccess(`Updated address group \"${name}\".`);
      } else {
        await api.createNetworkGroup(payload);
        setSuccess(`Created address group \"${name}\".`);
      }

      resetGroupForm();
      await refreshData();
    } catch (err) {
      setGroupFormError(err.message || "Failed to save address group");
    } finally {
      setBusyKey("");
    }
  }

  async function handleResyncGroup(group, sourceMeta, description) {
    if (!group?.id || !sourceMeta) return;

    setBusyKey(`resync:${group.id}`);
    setError("");
    setSuccess("");

    try {
      const nextMeta = {
        ...sourceMeta,
        syncedAt: new Date().toISOString(),
      };
      const cidrs = resolveSnapshotCidrs(nextMeta, metadata, groupNetworksById, groupsById);

      if (cidrs.length === 0) {
        throw new Error("Re-sync returned no CIDRs for this address group.");
      }

      await api.updateNetworkGroup(group.id, {
        name: group.name,
        kind: group.kind || "CUSTOM",
        cidrs,
        description: buildDescriptionWithSourceMeta(description, nextMeta),
      });

      setSuccess(`Re-synced address group \"${group.name}\".`);
      await refreshData();
    } catch (err) {
      setError(err.message || "Failed to re-sync address group");
    } finally {
      setBusyKey("");
    }
  }

  const coveragePct = simulation.totalFlows > 0
    ? Math.round((simulation.matchedFlowCount / simulation.totalFlows) * 100)
    : 0;

  const inputClass =
    "bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary";

  const simulationRows = loading ? [] : displayedRows;

  return (
    <div className="max-w-[1400px] mx-auto p-6 flex flex-col gap-3">
      <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">Firewall Simulator</h2>
            <p className="text-sm text-slate-500">
              Simulate ordered firewall rules against all correlated client-to-server flows.
            </p>
          </div>
          <button
            type="button"
            onClick={refreshData}
            disabled={loading || !!busyKey}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
          >
            <Icon name="refresh" size={14} />
            Refresh Data
          </button>
        </div>
      </div>

      {error && (
        <div className="px-3 py-2 text-xs text-danger bg-red-50 border border-red-200 rounded-lg">
          {error}
        </div>
      )}
      {success && (
        <div className="px-3 py-2 text-xs text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg">
          {success}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-2">
        <div className="bg-white border border-neutral-200 rounded-xl px-3 py-2.5 shadow-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 font-medium">Correlated Flows</div>
          <div className="text-base font-semibold text-slate-900 mt-1">{formatInt(simulation.totalFlows)}</div>
        </div>
        <div className="bg-white border border-neutral-200 rounded-xl px-3 py-2.5 shadow-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 font-medium">Matched</div>
          <div className="text-base font-semibold text-slate-900 mt-1">{formatInt(simulation.matchedFlowCount)}</div>
        </div>
        <div className="bg-white border border-red-200 rounded-xl px-3 py-2.5 shadow-sm bg-red-50/50">
          <div className="text-[11px] uppercase tracking-wider text-red-500 font-medium">Unmatched</div>
          <div className="text-base font-semibold text-red-700 mt-1">{formatInt(simulation.unmatchedFlowCount)}</div>
        </div>
        <div className="bg-white border border-neutral-200 rounded-xl px-3 py-2.5 shadow-sm">
          <div className="text-[11px] uppercase tracking-wider text-slate-500 font-medium">Coverage</div>
          <div className="text-base font-semibold text-slate-900 mt-1">{coveragePct}%</div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
        <div className="xl:col-span-2 flex flex-col gap-3">
          <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-900">Rule Set</h3>
              <div className="flex items-center gap-2 flex-wrap justify-end">
                <input
                  ref={importRulesInputRef}
                  type="file"
                  accept=".json,application/json"
                  className="hidden"
                  onChange={handleImportRulesFile}
                />
                <button
                  type="button"
                  onClick={() => importRulesInputRef.current?.click()}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors"
                >
                  <Icon name="upload_file" size={14} />
                  Import JSON
                </button>
                <button
                  type="button"
                  onClick={handleExportRules}
                  disabled={rules.length === 0}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
                >
                  <Icon name="download" size={14} />
                  Export JSON
                </button>
                <button
                  type="button"
                  onClick={clearRules}
                  disabled={rules.length === 0}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium text-slate-500 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
                >
                  <Icon name="delete" size={14} />
                  Clear Rules
                </button>
              </div>
            </div>

            <form
              onSubmit={handleAddRule}
              className="rounded-xl border border-neutral-200 bg-neutral-50/60 p-3"
            >
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
                <div className="lg:col-span-4 rounded-lg border border-neutral-200 bg-white p-3">
                  <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-2">
                    Rule Identity
                  </p>
                  <input
                    value={ruleForm.name}
                    onChange={(event) => updateRuleForm("name", event.target.value)}
                    placeholder="Rule name (optional)"
                    className={inputClass}
                  />
                </div>

                <div className="lg:col-span-4 rounded-lg border border-neutral-200 bg-white p-3">
                  <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-2">
                    Source Match
                  </p>
                  <div className="flex flex-col gap-2">
                    <select
                      value={ruleForm.sourceType}
                      onChange={(event) => updateRuleForm("sourceType", event.target.value)}
                      className={inputClass}
                    >
                      <option value="ANY">Any Source</option>
                      <option value="IP_CIDR">Source IP/CIDR</option>
                      <option value="GROUP">Source Address Group</option>
                    </select>

                    {ruleForm.sourceType === "IP_CIDR" && (
                      <input
                        value={ruleForm.sourceValue}
                        onChange={(event) => updateRuleForm("sourceValue", event.target.value)}
                        placeholder="10.0.0.0/24 or 10.0.0.5"
                        className={inputClass}
                      />
                    )}
                    {ruleForm.sourceType === "GROUP" && (
                      <select
                        value={ruleForm.sourceGroupId}
                        onChange={(event) => updateRuleForm("sourceGroupId", event.target.value)}
                        className={inputClass}
                      >
                        <option value="">Select source group</option>
                        {groups.map((group) => (
                          <option key={`source-group-${group.id}`} value={String(group.id)}>
                            {group.name}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                </div>

                <div className="lg:col-span-4 rounded-lg border border-neutral-200 bg-white p-3">
                  <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-2">
                    Destination Match
                  </p>
                  <div className="flex flex-col gap-2">
                    <select
                      value={ruleForm.destinationType}
                      onChange={(event) => updateRuleForm("destinationType", event.target.value)}
                      className={inputClass}
                    >
                      <option value="ANY">Any Destination</option>
                      <option value="IP_CIDR">Destination IP/CIDR</option>
                      <option value="GROUP">Destination Address Group</option>
                    </select>

                    {ruleForm.destinationType === "IP_CIDR" && (
                      <input
                        value={ruleForm.destinationValue}
                        onChange={(event) => updateRuleForm("destinationValue", event.target.value)}
                        placeholder="172.16.2.0/24 or 172.16.2.10"
                        className={inputClass}
                      />
                    )}
                    {ruleForm.destinationType === "GROUP" && (
                      <select
                        value={ruleForm.destinationGroupId}
                        onChange={(event) => updateRuleForm("destinationGroupId", event.target.value)}
                        className={inputClass}
                      >
                        <option value="">Select destination group</option>
                        {groups.map((group) => (
                          <option key={`destination-group-${group.id}`} value={String(group.id)}>
                            {group.name}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                </div>

                <div className="lg:col-span-8 rounded-lg border border-neutral-200 bg-white p-3">
                  <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-2">
                    Service Match
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <select
                      value={ruleForm.protocol}
                      onChange={(event) => updateRuleForm("protocol", event.target.value)}
                      className={inputClass}
                    >
                      {RULE_PROTOCOL_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <input
                      value={ruleForm.destinationPort}
                      onChange={(event) => updateRuleForm("destinationPort", event.target.value)}
                      placeholder={ruleForm.protocol === "1" ? "ICMP uses destination port 0" : "Destination port (blank = Any)"}
                      className={inputClass}
                      disabled={ruleForm.protocol === "1"}
                    />
                  </div>
                  <p className="text-[11px] text-slate-500 mt-2">
                    Protocol and destination port are evaluated together for each rule.
                    {ruleForm.protocol === "1" ? " ICMP is fixed to port 0." : ""}
                  </p>
                </div>

                <div className="lg:col-span-4 flex lg:justify-end lg:items-end">
                  <button
                    type="submit"
                    className="w-full lg:w-auto bg-primary hover:bg-primary-dark text-white font-semibold px-4 py-2 rounded-lg text-sm transition-colors"
                  >
                    Add Rule
                  </button>
                </div>
              </div>
            </form>

            {ruleFormError && (
              <p className="text-xs text-danger mt-2">{ruleFormError}</p>
            )}

            <div className="mt-3 overflow-auto border border-neutral-200 rounded-xl">
              <table className="w-full text-xs">
                <thead className="bg-neutral-50 text-slate-500 uppercase">
                  <tr>
                    <th className="text-left font-medium px-3 py-2">Order</th>
                    <th className="text-left font-medium px-3 py-2">Rule</th>
                    <th className="text-left font-medium px-3 py-2">Source</th>
                    <th className="text-left font-medium px-3 py-2">Destination</th>
                    <th className="text-left font-medium px-3 py-2">Protocol</th>
                    <th className="text-left font-medium px-3 py-2">Dst Port</th>
                    <th className="text-right font-medium px-3 py-2">Matched Flows</th>
                    <th className="text-right font-medium px-3 py-2">Bytes</th>
                    <th className="text-right font-medium px-3 py-2">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-200">
                  {rules.map((rule, index) => {
                    const stats = simulation.ruleStats[index] || {
                      matchedFlows: 0,
                      matchedSessions: 0,
                      matchedBytes: 0,
                    };

                    let sourceLabel = "Any";
                    if (rule.sourceType === "IP_CIDR") {
                      sourceLabel = rule.sourceValue;
                    } else if (rule.sourceType === "GROUP") {
                      sourceLabel = groupsById.get(String(rule.sourceGroupId))?.name || "(missing group)";
                    }

                    let destinationLabel = "Any";
                    if (rule.destinationType === "IP_CIDR") {
                      destinationLabel = rule.destinationValue;
                    } else if (rule.destinationType === "GROUP") {
                      destinationLabel = groupsById.get(String(rule.destinationGroupId))?.name || "(missing group)";
                    }

                    return (
                      <tr key={rule.id}>
                        <td className="px-3 py-2 text-slate-600">#{index + 1}</td>
                        <td className="px-3 py-2 text-slate-900 font-medium">{rule.name || `Rule ${index + 1}`}</td>
                        <td className="px-3 py-2 text-slate-600 font-mono">{sourceLabel}</td>
                        <td className="px-3 py-2 text-slate-600 font-mono">{destinationLabel}</td>
                        <td className="px-3 py-2 text-slate-600">{formatRuleProtocol(rule.protocol)}</td>
                        <td className="px-3 py-2 text-slate-600 font-mono">{formatRuleDestinationPort(rule)}</td>
                        <td className="px-3 py-2 text-right text-slate-700">{formatInt(stats.matchedFlows)}</td>
                        <td className="px-3 py-2 text-right text-slate-700">{formatBytes(stats.matchedBytes)}</td>
                        <td className="px-3 py-2 text-right">
                          <div className="inline-flex items-center gap-1">
                            <button
                              type="button"
                              onClick={() => moveRule(rule.id, -1)}
                              disabled={index === 0}
                              className="px-2 py-1 rounded border border-neutral-200 text-slate-500 hover:text-slate-700 hover:bg-neutral-100 disabled:opacity-40"
                              title="Move up"
                            >
                              <Icon name="arrow_upward" size={12} />
                            </button>
                            <button
                              type="button"
                              onClick={() => moveRule(rule.id, 1)}
                              disabled={index === rules.length - 1}
                              className="px-2 py-1 rounded border border-neutral-200 text-slate-500 hover:text-slate-700 hover:bg-neutral-100 disabled:opacity-40"
                              title="Move down"
                            >
                              <Icon name="arrow_downward" size={12} />
                            </button>
                            <button
                              type="button"
                              onClick={() => deleteRule(rule.id)}
                              className="px-2 py-1 rounded border border-red-200 text-red-500 hover:bg-red-50"
                              title="Delete"
                            >
                              <Icon name="delete" size={12} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  {rules.length === 0 && (
                    <tr>
                      <td colSpan={9} className="px-3 py-8 text-center text-slate-400">
                        No firewall rules yet. Add a rule to simulate hits against correlated flows.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm min-h-[20rem]">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-semibold text-slate-900">Correlated Flows</h3>
              <label className="inline-flex items-center gap-2 text-xs text-slate-600">
                <input
                  type="checkbox"
                  checked={showUnmatchedOnly}
                  onChange={(event) => setShowUnmatchedOnly(event.target.checked)}
                />
                Show unmatched only
              </label>
            </div>
            <p className="text-xs text-slate-500 mb-3">
              Flows with no matching rule are highlighted in light red.
            </p>

            <div className="overflow-auto border border-neutral-200 rounded-xl max-h-[32rem]">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-neutral-50 text-slate-500 uppercase">
                  <tr>
                    <th className="text-left font-medium px-3 py-2">Matched Rule</th>
                    <th className="text-left font-medium px-3 py-2">Client (Source)</th>
                    <th className="text-left font-medium px-3 py-2">Server (Destination)</th>
                    <th className="text-left font-medium px-3 py-2">Dst Port</th>
                    <th className="text-left font-medium px-3 py-2">Protocol</th>
                    <th className="text-right font-medium px-3 py-2">Sessions</th>
                    <th className="text-right font-medium px-3 py-2">Bytes</th>
                    <th className="text-left font-medium px-3 py-2">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-200">
                  {simulationRows.slice(0, 1000).map((row) => {
                    const matchedRule = row.matchedRuleIndex >= 0 ? rules[row.matchedRuleIndex] : null;
                    return (
                      <tr
                        key={row.id}
                        className={row.matchedRuleIndex < 0 ? "bg-red-50/70 hover:bg-red-100/70" : "hover:bg-neutral-50"}
                      >
                        <td className="px-3 py-2 text-slate-700">
                          {matchedRule ? (matchedRule.name || `Rule ${row.matchedRuleIndex + 1}`) : (
                            <span className="text-red-700 font-medium">No Rule</span>
                          )}
                        </td>
                        <td className="px-3 py-2 text-slate-700 font-mono">{row.client_ip}</td>
                        <td className="px-3 py-2 text-slate-700 font-mono">{row.server_ip}</td>
                        <td className="px-3 py-2 text-slate-600 font-mono">{row.server_port ?? "-"}</td>
                        <td className="px-3 py-2 text-slate-600">
                          {PROTOCOL_NAMES[row.protocol] || row.protocol}
                        </td>
                        <td className="px-3 py-2 text-right text-slate-600">{formatInt(row.sessionCount)}</td>
                        <td className="px-3 py-2 text-right text-slate-600">{formatBytes(row.totalBytes)}</td>
                        <td className="px-3 py-2 text-slate-600 whitespace-nowrap">
                          {row.last_seen ? new Date(row.last_seen).toLocaleString() : "-"}
                        </td>
                      </tr>
                    );
                  })}
                  {simulationRows.length > 1000 && (
                    <tr>
                      <td colSpan={8} className="px-3 py-3 text-center text-slate-500 font-medium bg-neutral-50/50">
                        ... and {formatInt(simulationRows.length - 1000)} more flows
                      </td>
                    </tr>
                  )}
                  {!loading && simulationRows.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-3 py-8 text-center text-slate-400">
                        {showUnmatchedOnly
                          ? "All flows are matched by at least one rule."
                          : "No correlated flows found."}
                      </td>
                    </tr>
                  )}
                  {loading && (
                    <tr>
                      <td colSpan={8} className="px-3 py-8 text-center">
                        <div className="mx-auto w-full max-w-md flex flex-col gap-2">
                          <div className="flex items-center justify-center gap-1.5 text-slate-500">
                            <Icon name="progress_activity" size={14} className="animate-spin text-primary" />
                            <span>Loading correlated flows...</span>
                            {flowFetchProgress.total > 0 && (
                              <span className="font-medium text-slate-700">{flowFetchProgress.percent}%</span>
                            )}
                          </div>
                          <div className="h-2 w-full rounded-full overflow-hidden bg-neutral-100">
                            <div
                              className={`h-full rounded-full bg-primary transition-all duration-300 ${
                                flowFetchProgress.total > 0 ? "" : "animate-pulse w-1/3"
                              }`}
                              style={
                                flowFetchProgress.total > 0
                                  ? { width: `${flowFetchProgress.percent}%` }
                                  : undefined
                              }
                            />
                          </div>
                          <p className="text-[11px] text-slate-400">
                            {flowFetchProgress.total > 0
                              ? `${formatInt(flowFetchProgress.loaded)} of ${formatInt(flowFetchProgress.total)} flows fetched`
                              : "Preparing first results page..."}
                          </p>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-3">
          <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
            <h3 className="text-sm font-semibold text-slate-900 mb-3">Address Group Builder</h3>

            <div className="grid grid-cols-3 gap-1 rounded-lg bg-neutral-100 p-1 mb-3 text-xs">
              <button
                type="button"
                onClick={() => setGroupMode("static")}
                className={`px-2 py-1 rounded-md transition-colors ${groupMode === "static" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500"}`}
              >
                Static
              </button>
              <button
                type="button"
                onClick={() => setGroupMode("tag")}
                className={`px-2 py-1 rounded-md transition-colors ${groupMode === "tag" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500"}`}
              >
                Tag Snapshot
              </button>
              <button
                type="button"
                onClick={() => setGroupMode("container")}
                className={`px-2 py-1 rounded-md transition-colors ${groupMode === "container" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500"}`}
              >
                Container Snapshot
              </button>
            </div>

            <form onSubmit={handleSaveGroup} className="flex flex-col gap-2">
              <input
                value={groupForm.name}
                onChange={(event) => updateGroupForm("name", event.target.value)}
                placeholder="Address group name"
                className={inputClass}
              />

              {groupMode === "static" && (
                <textarea
                  rows={4}
                  value={groupForm.staticCidrs}
                  onChange={(event) => updateGroupForm("staticCidrs", event.target.value)}
                  placeholder="One CIDR/IP per line or comma-separated"
                  className={inputClass}
                />
              )}

              {groupMode === "tag" && (
                <>
                  <input
                    value={groupForm.tagKey}
                    onChange={(event) => updateGroupForm("tagKey", event.target.value)}
                    placeholder="Tag key (example: environment)"
                    className={inputClass}
                  />
                  <input
                    value={groupForm.tagValue}
                    onChange={(event) => updateGroupForm("tagValue", event.target.value)}
                    placeholder="Tag value (optional)"
                    className={inputClass}
                  />
                  <select
                    value={groupForm.tagContainerGroupId}
                    onChange={(event) => updateGroupForm("tagContainerGroupId", event.target.value)}
                    className={inputClass}
                  >
                    <option value="">
                      {hasContainerGroups ? "Any container scope" : "Any group scope"}
                    </option>
                    {containerSourceGroups.map((group) => (
                      <option key={`tag-container-${group.id}`} value={String(group.id)}>
                        {group.name}
                      </option>
                    ))}
                  </select>
                </>
              )}

              {groupMode === "container" && (
                <>
                  {!hasContainerGroups && (
                    <p className="text-[11px] text-slate-500">
                      No groups are typed as CONTAINER yet. Using all network groups as source options.
                    </p>
                  )}
                  <div className="border border-neutral-200 rounded-lg bg-white p-2">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[11px] uppercase tracking-wider text-slate-500 font-medium">
                        {hasContainerGroups ? "Container Sources" : "Source Groups"}
                      </span>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={selectAllContainerSourceGroups}
                          className="text-[11px] text-slate-500 hover:text-primary"
                        >
                          Select All
                        </button>
                        <button
                          type="button"
                          onClick={clearContainerSourceGroups}
                          className="text-[11px] text-slate-500 hover:text-primary"
                        >
                          Clear
                        </button>
                      </div>
                    </div>

                    <div className="max-h-40 overflow-auto space-y-1">
                      {containerSourceGroups.map((group) => {
                        const groupId = String(group.id);
                        const selectedIds = Array.isArray(groupForm.containerSourceGroupIds)
                          ? groupForm.containerSourceGroupIds
                          : [];
                        const isSelected = selectedIds.includes(groupId);

                        return (
                          <label
                            key={`container-source-${group.id}`}
                            className={`flex items-center gap-2 rounded px-2 py-1 text-xs cursor-pointer ${
                              isSelected ? "bg-primary/10 text-slate-900" : "hover:bg-neutral-50 text-slate-600"
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => toggleContainerSourceGroup(groupId)}
                            />
                            <span className="truncate">
                              {group.name}
                              <span className="text-slate-400 ml-1">({group.kind})</span>
                            </span>
                          </label>
                        );
                      })}
                      {containerSourceGroups.length === 0 && (
                        <p className="text-xs text-slate-400 px-1 py-2">No source groups available.</p>
                      )}
                    </div>
                  </div>
                  <p className="text-[11px] text-slate-500">
                    Selected groups: {formatInt(Array.isArray(groupForm.containerSourceGroupIds) ? groupForm.containerSourceGroupIds.length : 0)}
                  </p>
                </>
              )}

              <textarea
                rows={2}
                value={groupForm.description}
                onChange={(event) => updateGroupForm("description", event.target.value)}
                placeholder="Description (optional)"
                className={inputClass}
              />

              {groupFormError && (
                <p className="text-xs text-danger">{groupFormError}</p>
              )}

              <button
                type="submit"
                disabled={loading || !!busyKey}
                className="bg-primary hover:bg-primary-dark text-white font-semibold px-3 py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
              >
                {busyKey === "save-group" ? "Saving..." : "Save Address Group"}
              </button>
            </form>
          </div>

          <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
            <h3 className="text-sm font-semibold text-slate-900 mb-2">Snapshot Groups</h3>
            <p className="text-xs text-slate-500 mb-3">
              Dynamic snapshots are stored as static CIDR groups. Re-sync refreshes the static CIDR set.
            </p>

            <div className="space-y-2 max-h-[24rem] overflow-auto">
              {dynamicGroups.map(({ group, sourceMeta, description }) => {
                const sourceLabel = formatSourceMeta(sourceMeta, groupsById);
                const cidrCount = getGroupCidrs(group).length;

                return (
                  <div key={`snapshot-${group.id}`} className="border border-neutral-200 rounded-lg p-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="text-sm font-medium text-slate-800">{group.name}</div>
                        <div className="text-[11px] text-slate-500">{sourceLabel || "Snapshot"}</div>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleResyncGroup(group, sourceMeta, description)}
                        disabled={!!busyKey}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded border border-neutral-200 text-[11px] text-slate-600 hover:bg-neutral-100 disabled:opacity-50"
                      >
                        <Icon name="sync" size={12} />
                        {busyKey === `resync:${group.id}` ? "Syncing..." : "Re-sync"}
                      </button>
                    </div>
                    <div className="mt-1 text-[11px] text-slate-500">
                      {formatInt(cidrCount)} CIDR{cidrCount === 1 ? "" : "s"}
                    </div>
                  </div>
                );
              })}

              {dynamicGroups.length === 0 && (
                <div className="text-xs text-slate-400 border border-dashed border-neutral-200 rounded-lg p-3">
                  No dynamic snapshot groups yet.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
