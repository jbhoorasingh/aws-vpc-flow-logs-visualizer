import { useCallback, useEffect, useRef, useState } from "react";
import { api, extractResults } from "../lib/api";
import { formatInt } from "../lib/graph";
import Icon from "../components/Icon";

function formatDateTime(value) {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "-";
  return dt.toLocaleString();
}

function parseCommaList(value) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseCidrList(value) {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatGroupCidrs(group) {
  const cidrs = Array.isArray(group?.cidrs) && group.cidrs.length
    ? group.cidrs
    : group?.cidr
      ? [group.cidr]
      : [];
  if (cidrs.length === 0) return "No CIDR";
  if (cidrs.length <= 2) return cidrs.join(", ");
  return `${cidrs[0]}, ${cidrs[1]} (+${cidrs.length - 2})`;
}

const EMPTY_GROUP_FORM = {
  id: "",
  name: "",
  kind: "CUSTOM",
  cidrs: "",
  tags: "",
  description: "",
};

const SETTINGS_EXPORT_VERSION = 1;
const EXPORT_PAGE_SIZE = 500;

async function listAllPages(listFn, pageSize = EXPORT_PAGE_SIZE) {
  let page = 1;
  const results = [];

  for (;;) {
    const response = await listFn({ page, page_size: pageSize });
    const chunk = extractResults(response);
    results.push(...chunk);

    if (!Array.isArray(response?.results)) {
      break;
    }

    const total = Number(response?.count || 0);
    if (total > 0 && results.length >= total) {
      break;
    }
    if (chunk.length < pageSize) {
      break;
    }

    page += 1;
  }

  return results;
}

function fileTimestamp() {
  return new Date().toISOString().replaceAll(":", "-").split(".")[0];
}

function downloadJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = window.URL.createObjectURL(blob);
  const anchor = window.document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  window.document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
}

async function readJsonFile(file) {
  const rawText = await file.text();
  try {
    return JSON.parse(rawText);
  } catch {
    throw new Error("Selected file is not valid JSON.");
  }
}

function getImportItems(payload, acceptedKeys, entityLabel) {
  if (Array.isArray(payload)) {
    return payload;
  }
  if (!payload || typeof payload !== "object") {
    throw new Error(`${entityLabel} JSON must be an array or object.`);
  }

  for (const key of acceptedKeys) {
    if (Array.isArray(payload[key])) {
      return payload[key];
    }
  }

  throw new Error(
    `${entityLabel} JSON must be an array or include one of: ${acceptedKeys.join(", ")}.`,
  );
}

function normalizeIpMetadataImportItems(items) {
  return items.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`Asset item ${index + 1} must be an object.`);
    }

    const ipAddress = String(item.ip_address || "").trim();
    if (!ipAddress) {
      throw new Error(`Asset item ${index + 1} is missing ip_address.`);
    }

    const normalized = { ip_address: ipAddress };
    const textFields = [
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
    ];

    textFields.forEach((field) => {
      if (item[field] == null) return;
      const value = String(item[field]).trim();
      if (!value) return;
      normalized[field] = field === "asset_kind" ? value.toUpperCase() : value;
    });

    if (item.tags !== undefined) {
      normalized.tags = item.tags;
    }
    if (item.attributes !== undefined) {
      normalized.attributes = item.attributes;
    }

    return normalized;
  });
}

function normalizeNetworkGroupImportItems(items) {
  return items.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(`Network group item ${index + 1} must be an object.`);
    }

    const name = String(item.name || "").trim();
    if (!name) {
      throw new Error(`Network group item ${index + 1} is missing name.`);
    }

    const normalized = { name };
    const kind = String(item.kind || "").trim();
    if (kind) {
      normalized.kind = kind.toUpperCase();
    }

    const cidrsRaw = Array.isArray(item.cidrs)
      ? item.cidrs
      : item.cidr
        ? [item.cidr]
        : [];
    const cidrs = cidrsRaw.map((value) => String(value || "").trim()).filter(Boolean);
    if (cidrs.length === 0) {
      throw new Error(`Network group "${name}" is missing cidrs.`);
    }
    normalized.cidrs = cidrs;

    if (Array.isArray(item.tags)) {
      normalized.tags = item.tags.map((value) => String(value || "").trim()).filter(Boolean);
    } else if (typeof item.tags === "string") {
      normalized.tags = parseCommaList(item.tags);
    }

    if (item.description != null) {
      normalized.description = String(item.description);
    }

    return normalized;
  });
}

export default function SettingsPage() {
  const [health, setHealth] = useState(null);
  const [imports, setImports] = useState([]);
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [workingKey, setWorkingKey] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [groupForm, setGroupForm] = useState(EMPTY_GROUP_FORM);
  const [groupFormSaving, setGroupFormSaving] = useState(false);
  const [groupFormError, setGroupFormError] = useState("");
  const assetImportInputRef = useRef(null);
  const groupImportInputRef = useRef(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError("");
    const errors = [];

    const [healthRes, importsRes, groupsRes] = await Promise.allSettled([
      api.getHealth(),
      api.listFlowLogImports(),
      api.listNetworkGroups(),
    ]);

    if (healthRes.status === "fulfilled") {
      setHealth(healthRes.value);
    } else {
      setHealth(null);
      errors.push(healthRes.reason?.message || "Failed to load health");
    }

    if (importsRes.status === "fulfilled") {
      setImports(extractResults(importsRes.value));
    } else {
      setImports([]);
      errors.push(importsRes.reason?.message || "Failed to load imports");
    }

    if (groupsRes.status === "fulfilled") {
      setGroups(extractResults(groupsRes.value));
    } else {
      setGroups([]);
      errors.push(groupsRes.reason?.message || "Failed to load network groups");
    }

    if (errors.length > 0) {
      setError(errors.join(" | "));
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  function resetGroupForm() {
    setGroupForm(EMPTY_GROUP_FORM);
    setGroupFormError("");
  }

  function fillGroupForm(group) {
    const cidrs = Array.isArray(group?.cidrs) && group.cidrs.length
      ? group.cidrs
      : group?.cidr
        ? [group.cidr]
        : [];

    setGroupForm({
      id: String(group.id),
      name: group.name || "",
      kind: group.kind || "CUSTOM",
      cidrs: cidrs.join("\n"),
      tags: (group.tags || []).join(", "),
      description: group.description || "",
    });
    setGroupFormError("");
    setSuccess("");
  }

  async function handleDeleteAllLogs() {
    if (!window.confirm("Delete all raw flow logs and correlated sessions?")) return;

    setWorkingKey("delete-all-logs");
    setError("");
    setSuccess("");
    try {
      const result = await api.purgeFlowLogs();
      setSuccess(
        `Deleted ${formatInt(result?.deleted_flow_logs ?? 0)} raw logs and ${formatInt(
          result?.deleted_correlated_flows ?? 0
        )} correlated sessions.`
      );
      await fetchData();
    } catch (err) {
      setError(err.message || "Failed to delete all logs");
    } finally {
      setWorkingKey("");
    }
  }

  async function handleDeleteImport(source, label) {
    if (!window.confirm(`Delete all logs for import: ${label}?`)) return;

    setWorkingKey(`delete-import:${source}`);
    setError("");
    setSuccess("");
    try {
      const result = await api.purgeFlowLogs(source);
      setSuccess(
        `Deleted ${formatInt(result?.deleted_flow_logs ?? 0)} logs from ${label}. Correlated sessions were rebuilt from remaining logs.`
      );
      await fetchData();
    } catch (err) {
      setError(err.message || "Failed to delete import logs");
    } finally {
      setWorkingKey("");
    }
  }

  async function handleDeleteAllGroups() {
    if (!window.confirm("Delete all network groups?")) return;

    setWorkingKey("delete-all-groups");
    setError("");
    setSuccess("");
    try {
      const result = await api.purgeAllNetworkGroups();
      setSuccess(
        `Deleted ${formatInt(result?.deleted_network_groups ?? 0)} network groups.`
      );
      resetGroupForm();
      await fetchData();
    } catch (err) {
      setError(err.message || "Failed to delete all groups");
    } finally {
      setWorkingKey("");
    }
  }

  async function handleDeleteGroup(group) {
    if (!group?.id) return;
    if (!window.confirm(`Delete group "${group.name}"?`)) return;

    const actionKey = `delete-group:${group.id}`;
    setWorkingKey(actionKey);
    setError("");
    setSuccess("");
    try {
      await api.deleteNetworkGroup(group.id);
      if (groupForm.id === String(group.id)) {
        resetGroupForm();
      }
      setSuccess(`Deleted group "${group.name}".`);
      await fetchData();
    } catch (err) {
      setError(err.message || "Failed to delete group");
    } finally {
      setWorkingKey("");
    }
  }

  async function handleSaveGroup(e) {
    e.preventDefault();
    setGroupFormError("");
    setError("");
    setSuccess("");

    const name = groupForm.name.trim();
    if (!name) {
      setGroupFormError("Group name is required.");
      return;
    }
    const cidrs = parseCidrList(groupForm.cidrs);
    if (cidrs.length === 0) {
      setGroupFormError("Provide at least one CIDR.");
      return;
    }

    const payload = {
      name,
      kind: groupForm.kind,
      cidrs,
    };

    const tags = parseCommaList(groupForm.tags);
    if (tags.length > 0) payload.tags = tags;
    const description = groupForm.description.trim();
    if (description) payload.description = description;

    setGroupFormSaving(true);
    try {
      if (groupForm.id) {
        await api.updateNetworkGroup(groupForm.id, payload);
        setSuccess(`Updated group "${name}".`);
      } else {
        await api.createNetworkGroup(payload);
        setSuccess(`Created group "${name}".`);
      }
      resetGroupForm();
      await fetchData();
    } catch (err) {
      setGroupFormError(err.message || "Failed to save group");
    } finally {
      setGroupFormSaving(false);
    }
  }

  async function handleExportAssetsJson() {
    setWorkingKey("export-assets-json");
    setError("");
    setSuccess("");
    try {
      const assets = await listAllPages((params) => api.listIpMetadata(params));
      const items = normalizeIpMetadataImportItems(assets);

      downloadJson(`assets-${fileTimestamp()}.json`, {
        version: SETTINGS_EXPORT_VERSION,
        type: "assets",
        exported_at: new Date().toISOString(),
        item_count: items.length,
        items,
      });
      setSuccess(`Exported ${formatInt(items.length)} assets to JSON.`);
    } catch (err) {
      setError(err.message || "Failed to export assets JSON.");
    } finally {
      setWorkingKey("");
    }
  }

  async function handleImportAssetsJson(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    setWorkingKey("import-assets-json");
    setError("");
    setSuccess("");
    try {
      const parsed = await readJsonFile(file);
      const importedItems = getImportItems(parsed, ["items", "assets", "ip_metadata"], "Assets");
      const items = normalizeIpMetadataImportItems(importedItems);
      const result = await api.importIpMetadata(items);
      setSuccess(
        `Imported assets from ${file.name}. Created ${formatInt(result?.created || 0)}, updated ${formatInt(result?.updated || 0)}.`,
      );
      await fetchData();
    } catch (err) {
      setError(err.message || "Failed to import assets JSON.");
    } finally {
      setWorkingKey("");
    }
  }

  async function handleExportGroupsJson() {
    setWorkingKey("export-groups-json");
    setError("");
    setSuccess("");
    try {
      const networkGroups = await listAllPages((params) => api.listNetworkGroups(params));
      const items = normalizeNetworkGroupImportItems(networkGroups);

      downloadJson(`network-groups-${fileTimestamp()}.json`, {
        version: SETTINGS_EXPORT_VERSION,
        type: "network-groups",
        exported_at: new Date().toISOString(),
        item_count: items.length,
        items,
      });
      setSuccess(`Exported ${formatInt(items.length)} network groups to JSON.`);
    } catch (err) {
      setError(err.message || "Failed to export network groups JSON.");
    } finally {
      setWorkingKey("");
    }
  }

  async function handleImportGroupsJson(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    setWorkingKey("import-groups-json");
    setError("");
    setSuccess("");
    try {
      const parsed = await readJsonFile(file);
      const importedItems = getImportItems(parsed, ["items", "network_groups", "groups"], "Network groups");
      const items = normalizeNetworkGroupImportItems(importedItems);
      const result = await api.importNetworkGroups(items);
      setSuccess(
        `Imported network groups from ${file.name}. Created ${formatInt(result?.created || 0)}, updated ${formatInt(result?.updated || 0)}.`,
      );
      await fetchData();
    } catch (err) {
      setError(err.message || "Failed to import network groups JSON.");
    } finally {
      setWorkingKey("");
    }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto flex flex-col gap-3">
      <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">Settings</h2>
            <p className="text-sm text-slate-500">
              Manage stored logs, assets, and network group data.
            </p>
          </div>
          <button
            onClick={fetchData}
            disabled={loading || !!workingKey || groupFormSaving}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
          >
            <Icon name="refresh" size={14} />
            Refresh
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

      <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
        <div className="flex items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">Import / Export JSON</h3>
            <p className="text-xs text-slate-500">
              Backup and restore assets and network groups.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="rounded-xl border border-neutral-200 p-3 bg-neutral-50/60">
            <div className="flex items-center justify-between gap-2 mb-2">
              <div>
                <p className="text-sm font-semibold text-slate-900">Assets</p>
                <p className="text-xs text-slate-500">
                  IP metadata entries: {formatInt(health?.ip_metadata ?? 0)}
                </p>
              </div>
            </div>
            <input
              ref={assetImportInputRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={handleImportAssetsJson}
            />
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => assetImportInputRef.current?.click()}
                disabled={loading || !!workingKey || groupFormSaving}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
              >
                <Icon name="upload_file" size={14} />
                {workingKey === "import-assets-json" ? "Importing..." : "Import JSON"}
              </button>
              <button
                type="button"
                onClick={handleExportAssetsJson}
                disabled={loading || !!workingKey || groupFormSaving}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
              >
                <Icon name="download" size={14} />
                {workingKey === "export-assets-json" ? "Exporting..." : "Export JSON"}
              </button>
            </div>
          </div>

          <div className="rounded-xl border border-neutral-200 p-3 bg-neutral-50/60">
            <div className="flex items-center justify-between gap-2 mb-2">
              <div>
                <p className="text-sm font-semibold text-slate-900">Network Groups</p>
                <p className="text-xs text-slate-500">
                  Groups: {formatInt(health?.network_groups ?? groups.length)}
                </p>
              </div>
            </div>
            <input
              ref={groupImportInputRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={handleImportGroupsJson}
            />
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => groupImportInputRef.current?.click()}
                disabled={loading || !!workingKey || groupFormSaving}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
              >
                <Icon name="upload_file" size={14} />
                {workingKey === "import-groups-json" ? "Importing..." : "Import JSON"}
              </button>
              <button
                type="button"
                onClick={handleExportGroupsJson}
                disabled={loading || !!workingKey || groupFormSaving}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
              >
                <Icon name="download" size={14} />
                {workingKey === "export-groups-json" ? "Exporting..." : "Export JSON"}
              </button>
            </div>
          </div>
        </div>

        <p className="text-[11px] text-slate-500 mt-2">
          Import merges by IP address for assets and by name for network groups.
        </p>
      </div>

      <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
        <div className="flex items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">Flow Logs</h3>
            <p className="text-xs text-slate-500">
              Delete all logs or remove a specific import source.
            </p>
          </div>
          <button
            onClick={handleDeleteAllLogs}
            disabled={loading || !!workingKey || groupFormSaving}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-danger hover:bg-red-600 transition-colors disabled:opacity-50"
          >
            <Icon name="delete_forever" size={14} />
            {workingKey === "delete-all-logs" ? "Deleting..." : "Delete All Logs"}
          </button>
        </div>

        <div className="flex flex-wrap gap-2 mb-3">
          <div className="px-2.5 py-1.5 rounded-lg bg-neutral-50 border border-neutral-200 text-xs text-slate-600">
            Raw Logs:{" "}
            <span className="font-semibold text-slate-900">
              {formatInt(health?.flow_log_entries ?? 0)}
            </span>
          </div>
          <div className="px-2.5 py-1.5 rounded-lg bg-neutral-50 border border-neutral-200 text-xs text-slate-600">
            Correlated Sessions:{" "}
            <span className="font-semibold text-slate-900">
              {formatInt(health?.correlated_flows ?? 0)}
            </span>
          </div>
          <div className="px-2.5 py-1.5 rounded-lg bg-neutral-50 border border-neutral-200 text-xs text-slate-600">
            Imports:{" "}
            <span className="font-semibold text-slate-900">
              {formatInt(imports.length)}
            </span>
          </div>
        </div>

        <div className="overflow-auto border border-neutral-200 rounded-xl">
          <table className="w-full text-xs">
            <thead className="bg-neutral-50 text-slate-500 uppercase">
              <tr>
                <th className="text-left font-medium px-3 py-2">Import</th>
                <th className="text-right font-medium px-3 py-2">Entries</th>
                <th className="text-left font-medium px-3 py-2">First Seen</th>
                <th className="text-left font-medium px-3 py-2">Last Seen</th>
                <th className="text-right font-medium px-3 py-2">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200">
              {imports.map((item) => (
                <tr key={`import:${item.source}`}>
                  <td className="px-3 py-2 text-slate-800 font-mono">{item.label}</td>
                  <td className="px-3 py-2 text-right text-slate-700">
                    {formatInt(item.entry_count || 0)}
                  </td>
                  <td className="px-3 py-2 text-slate-600">
                    {formatDateTime(item.first_seen)}
                  </td>
                  <td className="px-3 py-2 text-slate-600">
                    {formatDateTime(item.last_seen)}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button
                      onClick={() => handleDeleteImport(item.source, item.label)}
                      disabled={loading || !!workingKey || groupFormSaving}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium text-danger border border-red-200 hover:bg-red-50 transition-colors disabled:opacity-50"
                    >
                      <Icon name="delete" size={12} />
                      {workingKey === `delete-import:${item.source}` ? "Deleting..." : "Delete Import"}
                    </button>
                  </td>
                </tr>
              ))}
              {imports.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-slate-400">
                    {loading ? "Loading imports..." : "No imports found."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
        <div className="flex items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">Network Groups</h3>
            <p className="text-xs text-slate-500">
              Manage individual groups or remove all group definitions.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1.5 rounded-lg bg-neutral-50 border border-neutral-200 text-xs text-slate-600">
              Groups:{" "}
              <span className="font-semibold text-slate-900">
                {formatInt(health?.network_groups ?? groups.length)}
              </span>
            </span>
            <button
              onClick={handleDeleteAllGroups}
              disabled={loading || !!workingKey || groupFormSaving}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-danger hover:bg-red-600 transition-colors disabled:opacity-50"
            >
              <Icon name="delete_forever" size={14} />
              {workingKey === "delete-all-groups" ? "Deleting..." : "Delete All Groups"}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          <div className="border border-neutral-200 rounded-xl overflow-hidden">
            <div className="px-3 py-2 border-b border-neutral-200 bg-neutral-50 text-xs font-semibold text-slate-700">
              Individual Groups
            </div>
            <div className="max-h-80 overflow-auto divide-y divide-neutral-200">
              {groups.length === 0 ? (
                <div className="px-3 py-6 text-xs text-slate-400">No network groups defined.</div>
              ) : (
                groups.map((group) => (
                  <div key={group.id} className="px-3 py-2.5 flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-slate-800 truncate">{group.name}</div>
                      <div className="text-[11px] text-slate-500 truncate">
                        {group.kind || "CUSTOM"} • {formatGroupCidrs(group)}
                      </div>
                      {group.description && (
                        <div className="text-[11px] text-slate-400 truncate">{group.description}</div>
                      )}
                    </div>
                    <div className="shrink-0 flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => fillGroupForm(group)}
                        disabled={loading || !!workingKey || groupFormSaving}
                        className="px-2 py-1 rounded text-[11px] text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDeleteGroup(group)}
                        disabled={loading || groupFormSaving || workingKey === `delete-group:${group.id}`}
                        className="px-2 py-1 rounded text-[11px] text-danger border border-red-200 hover:bg-red-50 transition-colors disabled:opacity-50"
                      >
                        {workingKey === `delete-group:${group.id}` ? "Deleting..." : "Delete"}
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="border border-neutral-200 rounded-xl p-3">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-sm font-semibold text-slate-900">
                {groupForm.id ? "Edit Group" : "Create Group"}
              </h4>
              {groupForm.id && (
                <button
                  type="button"
                  onClick={resetGroupForm}
                  className="text-xs text-slate-500 hover:text-primary transition-colors"
                >
                  New Group
                </button>
              )}
            </div>

            <form onSubmit={handleSaveGroup} className="flex flex-col gap-2">
              <label className="flex flex-col gap-1">
                <span className="text-xs text-slate-500 font-medium">Group Name</span>
                <input
                  value={groupForm.name}
                  onChange={(e) => setGroupForm((current) => ({ ...current, name: e.target.value }))}
                  placeholder="prod-vpc"
                  className="bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary"
                />
              </label>

              <label className="flex flex-col gap-1">
                <span className="text-xs text-slate-500 font-medium">Kind</span>
                <select
                  value={groupForm.kind}
                  onChange={(e) => setGroupForm((current) => ({ ...current, kind: e.target.value }))}
                  className="bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-1.5 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="VPC">VPC</option>
                  <option value="CONTAINER">Container</option>
                  <option value="EXTERNAL">External</option>
                  <option value="CUSTOM">Custom</option>
                </select>
              </label>

              <label className="flex flex-col gap-1">
                <span className="text-xs text-slate-500 font-medium">CIDRs</span>
                <textarea
                  value={groupForm.cidrs}
                  onChange={(e) => setGroupForm((current) => ({ ...current, cidrs: e.target.value }))}
                  rows={3}
                  placeholder={"10.0.0.0/16,\n10.1.0.0/16"}
                  className="bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary resize-y"
                />
              </label>

              <label className="flex flex-col gap-1">
                <span className="text-xs text-slate-500 font-medium">Tags (comma-separated)</span>
                <input
                  value={groupForm.tags}
                  onChange={(e) => setGroupForm((current) => ({ ...current, tags: e.target.value }))}
                  placeholder="prod, private"
                  className="bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary"
                />
              </label>

              <label className="flex flex-col gap-1">
                <span className="text-xs text-slate-500 font-medium">Description</span>
                <textarea
                  value={groupForm.description}
                  onChange={(e) =>
                    setGroupForm((current) => ({ ...current, description: e.target.value }))
                  }
                  rows={2}
                  placeholder="Primary production ranges"
                  className="bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary resize-y"
                />
              </label>

              {groupFormError && (
                <p className="text-xs text-danger">{groupFormError}</p>
              )}

              <button
                type="submit"
                disabled={loading || !!workingKey || groupFormSaving}
                className="bg-primary hover:bg-primary-dark text-white font-semibold py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
              >
                {groupFormSaving ? "Saving..." : groupForm.id ? "Update Group" : "Create Group"}
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
