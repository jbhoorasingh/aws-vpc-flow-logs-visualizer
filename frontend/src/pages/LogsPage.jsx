import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import Icon from "../components/Icon";
import RawFlowEntriesTable from "../components/logs/RawFlowEntriesTable";

const RAW_CANONICAL_FIELDS = [
  "srcaddr",
  "dstaddr",
  "srcport",
  "dstport",
  "protocol",
  "action",
  "source",
  "interface_id",
  "log_status",
];

const RAW_ALIAS_FIELDS = ["addr.src", "addr.dst", "port.src", "port.dst", "proto", "ip.src", "ip.dst"];

const INSTANCE_ASSET_FIELD_PAIRS = [
  ["instance.name", "asset.name"],
  ["instance.owner", "asset.owner"],
  ["instance.account_owner", "asset.account_owner"],
  ["instance.region", "asset.region"],
  ["instance.az", "asset.az"],
  ["instance.availability_zone", "asset.availability_zone"],
  ["instance.instance_id", "asset.instance_id"],
  ["instance.interface_id", "asset.interface_id"],
  ["instance.type", "asset.type"],
  ["instance.instance_type", "asset.instance_type"],
  ["instance.state", "asset.state"],
  ["instance.provider", "asset.provider"],
  ["instance.kind", "asset.kind"],
  ["instance.asset_kind", "asset.asset_kind"],
];

const DEFAULT_VPC_LOG_FORMAT =
  "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status";

const EMPTY_RAW_FILTERS = {
  advanced_filter: "",
  since: "",
  until: "",
};

function toIsoDateTime(value) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "";
  return parsed.toISOString();
}

function toDateTimeLocalValue(value) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "";
  const year = parsed.getFullYear();
  const month = String(parsed.getMonth() + 1).padStart(2, "0");
  const day = String(parsed.getDate()).padStart(2, "0");
  const hours = String(parsed.getHours()).padStart(2, "0");
  const minutes = String(parsed.getMinutes()).padStart(2, "0");
  return `${year}-${month}-${day}T${hours}:${minutes}`;
}

function getTimeRangeError(since, until) {
  if (!since || !until) return "";
  const sinceDate = new Date(since);
  const untilDate = new Date(until);
  if (Number.isNaN(sinceDate.getTime()) || Number.isNaN(untilDate.getTime())) {
    return "Enter a valid start and end time.";
  }
  if (sinceDate > untilDate) {
    return "Start time must be before end time.";
  }
  return "";
}

function encodeFilterToken(value) {
  const text = String(value ?? "").trim();
  if (!text) return "";
  if (/[\s()]/.test(text)) {
    const escaped = text.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
    return `"${escaped}"`;
  }
  return text;
}

function appendAdvancedCondition(existing, condition) {
  const current = String(existing || "").trim();
  if (!condition) return current;
  if (!current) return condition;
  if (current.includes(condition)) return current;
  return `(${current}) and (${condition})`;
}

function buildQuickFilterCondition(field, value) {
  if (value == null || value === "") return "";
  const token = encodeFilterToken(value);
  if (!token) return "";

  switch (field) {
    case "srcaddr":
      return `addr.src == ${token}`;
    case "srcport":
      return `port.src == ${token}`;
    case "dstaddr":
      return `addr.dst == ${token}`;
    case "dstport":
      return `port.dst == ${token}`;
    case "protocol":
      return `protocol == ${token}`;
    case "interface_id":
      return `interface_id == ${token}`;
    default:
      return "";
  }
}

export default function LogsPage() {
  const PAGE_SIZE = 50;

  const [source, setSource] = useState("manual-upload");
  const [logFormat, setLogFormat] = useState(DEFAULT_VPC_LOG_FORMAT);
  const [lines, setLines] = useState("");
  const [files, setFiles] = useState([]);
  const [autoCorrelate, setAutoCorrelate] = useState(true);
  const [response, setResponse] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showFilterHelpModal, setShowFilterHelpModal] = useState(false);
  const [error, setError] = useState("");
  const [rawLogs, setRawLogs] = useState([]);
  const [rawCount, setRawCount] = useState(0);
  const [rawPage, setRawPage] = useState(1);
  const [rawLoading, setRawLoading] = useState(false);
  const [rawError, setRawError] = useState("");
  const [advancedFilterError, setAdvancedFilterError] = useState("");
  const [validatingAdvancedFilter, setValidatingAdvancedFilter] = useState(false);
  const [rawFilters, setRawFilters] = useState(() => ({ ...EMPTY_RAW_FILTERS }));
  const [rawDraft, setRawDraft] = useState(() => ({ ...EMPTY_RAW_FILTERS }));

  const fetchRawLogs = useCallback(async (page = 1, filters = {}) => {
    setRawLoading(true);
    setRawError("");
    try {
      const res = await api.listFlowLogs({
        page,
        page_size: PAGE_SIZE,
        advanced_filter: filters.advanced_filter || undefined,
        since: toIsoDateTime(filters.since) || undefined,
        until: toIsoDateTime(filters.until) || undefined,
      });
      setRawLogs(res?.results || []);
      setRawCount(res?.count || 0);
      setRawPage(page);
    } catch (err) {
      setRawError(err.message || "Failed to load raw flow entries");
    } finally {
      setRawLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRawLogs(1, rawFilters);
  }, [fetchRawLogs]);

  useEffect(() => {
    const value = rawDraft.advanced_filter.trim();
    setAdvancedFilterError("");

    if (!value) {
      setValidatingAdvancedFilter(false);
      return;
    }

    let cancelled = false;
    const timer = setTimeout(async () => {
      setValidatingAdvancedFilter(true);
      try {
        await api.validateAdvancedFlowFilter(value);
        if (!cancelled) {
          setAdvancedFilterError("");
        }
      } catch (err) {
        if (!cancelled) {
          setAdvancedFilterError(err.message || "Invalid filter syntax");
        }
      } finally {
        if (!cancelled) {
          setValidatingAdvancedFilter(false);
        }
      }
    }, 300);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [rawDraft.advanced_filter]);

  useEffect(() => {
    if (!showFilterHelpModal) return;

    function handleEsc(event) {
      if (event.key === "Escape") {
        setShowFilterHelpModal(false);
      }
    }

    window.addEventListener("keydown", handleEsc);
    return () => window.removeEventListener("keydown", handleEsc);
  }, [showFilterHelpModal]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setUploading(true);

    try {
      const hasFiles = files.length > 0;
      const hasLines = Boolean(lines.trim());
      if (!hasFiles && !hasLines) {
        throw new Error("Select one or more files, or paste flow log lines.");
      }

      const payload = new FormData();
      payload.append("source", source);
      payload.append("auto_correlate", String(autoCorrelate));
      payload.append("log_format", logFormat.trim());

      if (hasFiles) {
        for (const file of files) {
          payload.append("files", file);
        }
      }
      if (hasLines) {
        payload.append("lines", lines);
      }

      const data = await api.uploadFlowLogs(payload);
      setResponse(data);
      setLines("");
      setFiles([]);
      setShowUploadModal(false);
      fetchRawLogs(1, rawFilters);
    } catch (err) {
      setError(err.message || "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  async function handleRebuild() {
    setError("");
    try {
      const data = await api.rebuildCorrelation();
      setResponse(data);
      fetchRawLogs(1, rawFilters);
    } catch (err) {
      setError(err.message || "Rebuild failed");
    }
  }

  function buildFiltersFromDraft(draft = {}) {
    return {
      advanced_filter: (draft.advanced_filter || "").trim(),
      since: draft.since || "",
      until: draft.until || "",
    };
  }

  function applyFilters(filters) {
    const timeRangeError = getTimeRangeError(filters.since, filters.until);
    if (timeRangeError) {
      setRawError(timeRangeError);
      return false;
    }
    setRawError("");
    setRawFilters(filters);
    fetchRawLogs(1, filters);
    return true;
  }

  function handleApplyRawFilters(e) {
    e.preventDefault();
    if (advancedFilterError) {
      setRawError(`Advanced filter: ${advancedFilterError}`);
      return;
    }
    const nextFilters = buildFiltersFromDraft(rawDraft);
    applyFilters(nextFilters);
  }

  function handleResetRawFilters() {
    const empty = { ...EMPTY_RAW_FILTERS };
    setRawDraft(empty);
    setRawFilters(empty);
    setAdvancedFilterError("");
    setRawError("");
    fetchRawLogs(1, empty);
  }

  function handleQuickFilter({ field, value }) {
    if (value == null || value === "") return;

    const nextFilters = { ...rawFilters };

    if (field === "since") {
      nextFilters.since = toDateTimeLocalValue(value);
    } else if (field === "until") {
      nextFilters.until = toDateTimeLocalValue(value);
    } else {
      const condition = buildQuickFilterCondition(field, value);
      if (!condition) return;
      nextFilters.advanced_filter = appendAdvancedCondition(nextFilters.advanced_filter, condition);
    }

    setRawDraft(nextFilters);
    setAdvancedFilterError("");
    applyFilters(nextFilters);
  }

  const timeRangeError = getTimeRangeError(rawDraft.since, rawDraft.until);

  const inputClass =
    "bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary";

  return (
    <div className="w-full max-w-7xl mx-auto p-6 flex flex-col gap-3 min-w-0">
      <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">Raw Flow Explorer</h2>
            <p className="text-sm text-slate-500">
              Inspect original `FlowLogEntry` rows and drill into raw lines.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                setError("");
                setFiles([]);
                setLines("");
                setShowUploadModal(true);
              }}
              className="bg-primary hover:bg-primary-dark text-white font-semibold px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-1.5 shadow-lg shadow-primary/20"
            >
              <Icon name="add" size={16} />
              Add Flow Logs
            </button>
            <button
              type="button"
              onClick={handleRebuild}
              className="px-4 py-2 rounded-lg text-sm font-medium text-slate-600 border border-neutral-300 hover:bg-neutral-100 hover:text-slate-900 transition-colors"
            >
              Rebuild Correlation
            </button>
          </div>
        </div>
      </div>

      {error && (
        <p className="text-sm text-danger flex items-center gap-1 bg-white border border-red-200 rounded-lg px-3 py-2">
          <Icon name="error" size={16} />
          {error}
        </p>
      )}

      {response && (
        <pre className="bg-neutral-50 border border-neutral-200 rounded-lg p-3 text-xs text-slate-600 overflow-auto max-h-40 font-mono">
          {JSON.stringify(response, null, 2)}
        </pre>
      )}

      <div className="w-full min-w-0 flex flex-col gap-3">
        <div className="bg-white border border-neutral-200 rounded-2xl p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-slate-900">Raw Flow Filters</h3>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => setShowFilterHelpModal(true)}
                className="text-xs text-slate-500 hover:text-primary transition-colors inline-flex items-center gap-1"
              >
                <Icon name="help" size={14} />
                Help
              </button>
              <button
                type="button"
                onClick={handleResetRawFilters}
                className="text-xs text-slate-500 hover:text-primary transition-colors"
              >
                Reset
              </button>
            </div>
          </div>

          <form onSubmit={handleApplyRawFilters} className="flex flex-col gap-3">
            <div className="rounded-xl border border-neutral-200 bg-neutral-50/70 p-3">
              <div className="grid grid-cols-1 xl:grid-cols-12 gap-3 items-end">
                <label className="flex flex-col gap-1 xl:col-span-6">
                  <span className="text-[11px] uppercase tracking-wide text-slate-500 font-semibold">Advanced Filter</span>
                  <input
                    value={rawDraft.advanced_filter}
                    onChange={(e) =>
                      setRawDraft((draft) => ({
                        ...draft,
                        advanced_filter: e.target.value,
                      }))
                    }
                    placeholder="((addr.src == 10.108.1.1) or (addr.dst == 10.108.1.1)) and (protocol == icmp) and (port.dst == 80)"
                    className={`${inputClass} h-10`}
                  />
                </label>
                <label className="flex flex-col gap-1 xl:col-span-2">
                  <span className="text-[11px] uppercase tracking-wide text-slate-500 font-semibold">Start Time</span>
                  <input
                    type="datetime-local"
                    value={rawDraft.since}
                    onChange={(e) =>
                      setRawDraft((draft) => ({
                        ...draft,
                        since: e.target.value,
                      }))
                    }
                    className={`${inputClass} h-10`}
                  />
                </label>
                <label className="flex flex-col gap-1 xl:col-span-2">
                  <span className="text-[11px] uppercase tracking-wide text-slate-500 font-semibold">End Time</span>
                  <input
                    type="datetime-local"
                    value={rawDraft.until}
                    onChange={(e) =>
                      setRawDraft((draft) => ({
                        ...draft,
                        until: e.target.value,
                      }))
                    }
                    className={`${inputClass} h-10`}
                  />
                </label>
                <button
                  type="submit"
                  className="xl:col-span-2 h-10 bg-primary hover:bg-primary-dark text-white font-semibold px-4 rounded-lg text-sm transition-colors disabled:opacity-50 inline-flex items-center justify-center gap-1.5 shadow-lg shadow-primary/20"
                  disabled={rawLoading || validatingAdvancedFilter || !!advancedFilterError || !!timeRangeError}
                >
                  <Icon name="filter_list" size={16} />
                  {rawLoading ? "Loading..." : "Apply Filters"}
                </button>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-[11px] text-slate-400">
                Raw flow fields: addr.src, addr.dst, port.src, port.dst, protocol, action, source, interface_id,
                log_status. Instance/asset fields: instance.name, instance.owner, instance.region, instance.az,
                instance.tags.KEY (also `asset.*`). Protocol accepts names (`icmp`, `ipip`, `tcp`, `udp`) or numbers.
                Wildcards are supported for string values (for example `instance.name=*aws*`). Operators: =, ==, !=,
                and, or, parentheses. Click Start/End/Source/Destination/Proto/Iface cells to add quick filters.
                See Help for complete syntax and examples.
              </span>
              {timeRangeError && (
                <span className="text-[11px] text-danger">{timeRangeError}</span>
              )}
              {validatingAdvancedFilter && (
                <span className="text-[11px] text-slate-400">Validating syntax...</span>
              )}
              {advancedFilterError && (
                <span className="text-[11px] text-danger">{advancedFilterError}</span>
              )}
            </div>
          </form>
        </div>

        <RawFlowEntriesTable
          logs={rawLogs}
          page={rawPage}
          totalCount={rawCount}
          pageSize={PAGE_SIZE}
          loading={rawLoading}
          error={rawError}
          onPageChange={(page) => fetchRawLogs(page, rawFilters)}
          onQuickFilter={handleQuickFilter}
        />
      </div>

      {showUploadModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/45 backdrop-blur-[1px] flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-white border border-neutral-200 rounded-2xl shadow-2xl">
            <div className="flex items-center justify-between p-4 border-b border-neutral-200">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Icon name="upload_file" size={18} className="text-primary" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">Add Flow Logs</h3>
                  <p className="text-xs text-slate-500">
                    Bulk upload files or paste lines.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  if (uploading) return;
                  setShowUploadModal(false);
                  setFiles([]);
                }}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-neutral-100 transition-colors"
              >
                <Icon name="close" size={18} />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="p-4 flex flex-col gap-4">
              <label className="flex flex-col gap-1.5">
                <span className="text-xs text-slate-500 font-medium">Source Label</span>
                <input
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="prod-vpc-a"
                  className={inputClass}
                />
              </label>

              <label className="flex flex-col gap-1.5">
                <span className="text-xs text-slate-500 font-medium">Upload Flow Log Files</span>
                <input
                  type="file"
                  accept=".log,.txt,.gz,.log.gz"
                  multiple
                  onChange={(e) => setFiles(Array.from(e.target.files || []))}
                  className={`${inputClass} file:mr-3 file:rounded-lg file:border-0 file:bg-primary/10 file:text-primary file:px-3 file:py-1 file:text-xs file:font-medium file:cursor-pointer`}
                />
                <span className="text-[11px] text-slate-400">
                  {files.length === 0
                    ? "No files selected."
                    : `${files.length} file${files.length > 1 ? "s" : ""} selected`}
                </span>
              </label>

              <label className="flex flex-col gap-1.5">
                <span className="text-xs text-slate-500 font-medium">Flow Log Format</span>
                <input
                  value={logFormat}
                  onChange={(e) => setLogFormat(e.target.value)}
                  placeholder={DEFAULT_VPC_LOG_FORMAT}
                  className={`${inputClass} font-mono`}
                />
                <span className="text-[11px] text-slate-400">
                  Defaults to the standard AWS VPC format. Supports plain fields or token format like{" "}
                  <code>{"${srcaddr}"}</code>.
                </span>
              </label>

              <label className="flex flex-col gap-1.5">
                <span className="text-xs text-slate-500 font-medium">Or Paste VPC Flow Log Lines</span>
                <textarea
                  value={lines}
                  onChange={(e) => setLines(e.target.value)}
                  rows={6}
                  placeholder="2 123456789 eni-abc 10.0.1.10 10.0.2.20 55001 443 6 10 1200 1704067200 1704067260 ACCEPT OK"
                  className={`${inputClass} resize-none font-mono`}
                />
              </label>

              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoCorrelate}
                  onChange={(e) => setAutoCorrelate(e.target.checked)}
                  className="rounded border-neutral-300 accent-primary"
                />
                <span className="text-sm text-slate-600">Auto-correlate c2s/s2c flows</span>
              </label>

              <div className="flex gap-2 justify-end">
                <button
                  type="button"
                  onClick={() => {
                    if (uploading) return;
                    setShowUploadModal(false);
                    setFiles([]);
                  }}
                  className="px-4 py-2 rounded-lg text-sm text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors disabled:opacity-50"
                  disabled={uploading}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploading}
                  className="bg-primary hover:bg-primary-dark text-white font-semibold px-4 py-2 rounded-lg text-sm transition-colors disabled:opacity-50 flex items-center gap-1.5"
                >
                  <Icon name="cloud_upload" size={16} />
                  {uploading ? "Uploading..." : "Upload Logs"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showFilterHelpModal && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/45 backdrop-blur-[1px] flex items-center justify-center p-4"
          onClick={() => setShowFilterHelpModal(false)}
        >
          <div
            className="w-full max-w-3xl bg-white border border-neutral-200 rounded-2xl shadow-2xl max-h-[85vh] overflow-hidden"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-center justify-between p-4 border-b border-neutral-200">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Icon name="help" size={18} className="text-primary" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">Advanced Filter Syntax Help</h3>
                  <p className="text-xs text-slate-500">
                    Use this syntax in the Raw Flow Filters input to narrow logs quickly.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowFilterHelpModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-neutral-100 transition-colors"
              >
                <Icon name="close" size={18} />
              </button>
            </div>

            <div className="p-4 sm:p-5 overflow-y-auto flex flex-col gap-4 text-sm text-slate-600">
              <section className="flex flex-col gap-1.5">
                <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-700">Expression Format</h4>
                <p>
                  A filter is one or more conditions joined by <code>and</code> / <code>or</code>, with optional{" "}
                  <code>( ... )</code> grouping.
                </p>
                <p className="font-mono text-xs bg-neutral-50 border border-neutral-200 rounded-md px-2.5 py-2">
                  field operator value
                </p>
              </section>

              <section className="flex flex-col gap-1.5">
                <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-700">Operators</h4>
                <ul className="list-disc pl-5 space-y-1">
                  <li>
                    <code>=</code> and <code>==</code> both mean equals.
                  </li>
                  <li>
                    <code>!=</code> means not equals.
                  </li>
                  <li>
                    <code>and</code> and <code>or</code> are case-insensitive.
                  </li>
                </ul>
              </section>

              <section className="flex flex-col gap-1.5">
                <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-700">Values</h4>
                <ul className="list-disc pl-5 space-y-1">
                  <li>
                    IP fields accept single IPs and CIDRs, for example <code>addr.src == 10.0.0.10</code> or{" "}
                    <code>addr.src == 10.0.0.0/16</code>.
                  </li>
                  <li>
                    <code>protocol</code> accepts names (<code>icmp</code>, <code>ipip</code>, <code>tcp</code>, <code>udp</code>) or
                    numbers.
                  </li>
                  <li>String comparisons are case-insensitive.</li>
                  <li>
                    Use wildcards on string values: <code>*</code> (any sequence) and <code>?</code> (single char).
                  </li>
                  <li>
                    Quote values that include spaces or special characters, for example{" "}
                    <code>instance.tags.owner=&quot;Data Platform&quot;</code>.
                  </li>
                </ul>
              </section>

              <section className="flex flex-col gap-1.5">
                <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-700">Supported Fields</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="bg-neutral-50 border border-neutral-200 rounded-md p-3">
                    <p className="text-xs font-semibold text-slate-700 mb-1">Raw flow fields (all)</p>
                    <p className="text-[11px] font-medium text-slate-600 mb-1">Canonical</p>
                    <p className="font-mono text-xs leading-5 break-words">{RAW_CANONICAL_FIELDS.join(", ")}</p>
                    <p className="text-[11px] font-medium text-slate-600 mt-2 mb-1">Aliases</p>
                    <p className="font-mono text-xs leading-5 break-words">{RAW_ALIAS_FIELDS.join(", ")}</p>
                  </div>
                  <div className="bg-neutral-50 border border-neutral-200 rounded-md p-3">
                    <p className="text-xs font-semibold text-slate-700 mb-1">Instance/asset fields (all)</p>
                    <div className="font-mono text-xs leading-5">
                      {INSTANCE_ASSET_FIELD_PAIRS.map(([instanceField, assetField]) => (
                        <p key={instanceField} className="break-words">
                          {instanceField} | {assetField}
                        </p>
                      ))}
                      <p className="break-words mt-1">instance.tags.KEY | asset.tags.KEY</p>
                    </div>
                  </div>
                </div>
              </section>

              <section className="flex flex-col gap-1.5">
                <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-700">Examples</h4>
                <div className="bg-neutral-50 border border-neutral-200 rounded-md p-3 overflow-x-auto">
                  <pre className="font-mono text-xs text-slate-700 whitespace-pre-wrap">
{`((addr.src == 10.108.1.1) or (addr.dst == 10.108.1.1)) and (protocol == icmp) and (port.dst == 80)
instance.owner == 4442424324
instance.name = *aws*
instance.region = us-east-1 and instance.az = us-east-1d
instance.tags.environment = "prod"
asset.tags.team != "security" and action == ACCEPT
protocol == ipip`}
                  </pre>
                </div>
              </section>
            </div>

            <div className="p-4 border-t border-neutral-200 flex justify-end">
              <button
                type="button"
                onClick={() => setShowFilterHelpModal(false)}
                className="px-4 py-2 rounded-lg text-sm text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
