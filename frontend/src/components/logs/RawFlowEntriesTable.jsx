import { Fragment, useState } from "react";
import Icon from "../Icon";
import { formatBytes, formatInt } from "../../lib/graph";

const PROTOCOL_NAMES = { 1: "ICMP", 4: "IPIP", 6: "TCP", 17: "UDP" };

function formatTimestamp(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString([], {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function ActionBadge({ action }) {
  const normalized = (action || "").toUpperCase();
  const isAccept = normalized === "ACCEPT";
  const isReject = normalized === "REJECT";

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] leading-none font-medium ${
        isAccept
          ? "bg-success/10 text-success"
          : isReject
            ? "bg-danger/10 text-danger"
            : "bg-slate-100 text-slate-600"
      }`}
    >
      {normalized || "UNKNOWN"}
    </span>
  );
}

function QuickFilterValue({ children, title, onClick, className = "" }) {
  if (!onClick) {
    return <span className={className}>{children}</span>;
  }

  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={`rounded-sm hover:text-primary hover:underline decoration-dotted underline-offset-2 transition-colors ${className}`}
    >
      {children}
    </button>
  );
}

export default function RawFlowEntriesTable({
  logs,
  page,
  totalCount,
  pageSize,
  loading,
  error,
  onPageChange,
  onQuickFilter,
}) {
  const [expandedIds, setExpandedIds] = useState(() => new Set());
  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));
  const from = totalCount === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = totalCount === 0 ? 0 : Math.min(page * pageSize, totalCount);

  function toggleExpanded(id) {
    setExpandedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  return (
    <div className="w-full min-w-0 bg-white border border-neutral-200 rounded-2xl overflow-hidden shadow-sm">
      <div className="flex items-center justify-between px-4 py-3 border-b border-neutral-200 bg-neutral-50/50">
        <div>
          <h3 className="text-sm font-semibold text-slate-900">Raw Flow Entries</h3>
          <p className="text-xs text-slate-500">
            Original `FlowLogEntry` rows, not c2s/s2c-correlated sessions.
          </p>
        </div>
        <span className="text-xs text-slate-500">
          {totalCount > 0 ? `${from}-${to} of ${formatInt(totalCount)}` : "No results"}
        </span>
      </div>

      <div className="w-full">
        <table className="w-full table-fixed text-[11px] leading-tight">
          <thead className="sticky top-0 bg-neutral-50 text-[10px] uppercase text-slate-500">
            <tr>
              <th className="text-left font-medium px-1.5 py-1.5 w-7" />
              <th className="text-left font-medium px-1.5 py-1.5 w-[11%]">Start</th>
              <th className="text-left font-medium px-1.5 py-1.5 w-[11%]">End</th>
              <th className="text-left font-medium px-1.5 py-1.5 w-[8%]">Action</th>
              <th className="text-left font-medium px-1.5 py-1.5 w-[15%]">Source</th>
              <th className="text-left font-medium px-1.5 py-1.5 w-[15%]">Destination</th>
              <th className="text-left font-medium px-1 py-1.5 w-[4%]">Proto</th>
              <th className="text-right font-medium px-1 py-1.5 w-[6%]">Packets</th>
              <th className="text-right font-medium px-1.5 py-1.5 w-[8%]">Bytes</th>
              <th className="text-left font-medium px-1.5 py-1.5 w-[8%]">Ingest</th>
              <th className="text-left font-medium px-1.5 py-1.5 w-[9%]">Iface</th>
              <th className="text-left font-medium px-1.5 py-1.5 w-[5%]">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-neutral-200">
            {logs.map((log) => {
              const isExpanded = expandedIds.has(log.id);
              return (
                <Fragment key={log.id}>
                  <tr key={`row-${log.id}`} className="hover:bg-neutral-50 transition-colors align-top">
                    <td className="px-1.5 py-1">
                      <button
                        type="button"
                        onClick={() => toggleExpanded(log.id)}
                        className="p-0.5 rounded text-slate-400 hover:text-slate-700 hover:bg-neutral-100 transition-colors"
                        title={isExpanded ? "Collapse raw line" : "Expand raw line"}
                      >
                        <Icon name={isExpanded ? "expand_more" : "chevron_right"} size={16} />
                      </button>
                    </td>
                    <td className="px-1.5 py-1 text-slate-500 whitespace-nowrap" title={formatTimestamp(log.start_time)}>
                      <QuickFilterValue
                        onClick={
                          log.start_time
                            ? () => onQuickFilter?.({ field: "since", value: log.start_time })
                            : null
                        }
                        title="Add start time filter"
                      >
                        {formatTimestamp(log.start_time)}
                      </QuickFilterValue>
                    </td>
                    <td className="px-1.5 py-1 text-slate-500 whitespace-nowrap" title={formatTimestamp(log.end_time)}>
                      <QuickFilterValue
                        onClick={
                          log.end_time
                            ? () => onQuickFilter?.({ field: "until", value: log.end_time })
                            : null
                        }
                        title="Add end time filter"
                      >
                        {formatTimestamp(log.end_time)}
                      </QuickFilterValue>
                    </td>
                    <td className="px-1.5 py-1 whitespace-nowrap">
                      <ActionBadge action={log.action} />
                    </td>
                    <td className="px-1.5 py-1 text-slate-700 max-w-0">
                      <div className="truncate" title={`${log.srcaddr}${log.srcport != null ? `:${log.srcport}` : ""}`}>
                        {log.srcaddr ? (
                          <QuickFilterValue
                            className="font-mono text-slate-900"
                            onClick={() => onQuickFilter?.({ field: "srcaddr", value: log.srcaddr })}
                            title="Filter by source IP"
                          >
                            {log.srcaddr}
                          </QuickFilterValue>
                        ) : (
                          <span className="font-mono text-slate-900">-</span>
                        )}
                        {log.srcport != null && (
                          <>
                            <span className="text-slate-400">:</span>
                            <QuickFilterValue
                              className="font-mono text-slate-500"
                              onClick={() => onQuickFilter?.({ field: "srcport", value: log.srcport })}
                              title="Filter by source port"
                            >
                              {log.srcport}
                            </QuickFilterValue>
                          </>
                        )}
                      </div>
                    </td>
                    <td className="px-1.5 py-1 text-slate-700 max-w-0">
                      <div className="truncate" title={`${log.dstaddr}${log.dstport != null ? `:${log.dstport}` : ""}`}>
                        {log.dstaddr ? (
                          <QuickFilterValue
                            className="font-mono text-slate-900"
                            onClick={() => onQuickFilter?.({ field: "dstaddr", value: log.dstaddr })}
                            title="Filter by destination IP"
                          >
                            {log.dstaddr}
                          </QuickFilterValue>
                        ) : (
                          <span className="font-mono text-slate-900">-</span>
                        )}
                        {log.dstport != null && (
                          <>
                            <span className="text-slate-400">:</span>
                            <QuickFilterValue
                              className="font-mono text-slate-500"
                              onClick={() => onQuickFilter?.({ field: "dstport", value: log.dstport })}
                              title="Filter by destination port"
                            >
                              {log.dstport}
                            </QuickFilterValue>
                          </>
                        )}
                      </div>
                    </td>
                    <td className="px-1 py-1 text-slate-600 whitespace-nowrap text-[10px]">
                      <QuickFilterValue
                        onClick={
                          log.protocol != null
                            ? () => onQuickFilter?.({ field: "protocol", value: log.protocol })
                            : null
                        }
                        title="Filter by protocol"
                      >
                        {PROTOCOL_NAMES[log.protocol] || log.protocol}
                      </QuickFilterValue>
                    </td>
                    <td className="px-1 py-1 text-right text-slate-600 whitespace-nowrap">
                      {formatInt(log.packets)}
                    </td>
                    <td className="px-1.5 py-1 text-right text-slate-600 whitespace-nowrap">
                      {formatBytes(log.bytes)}
                    </td>
                    <td className="px-1.5 py-1 text-slate-600 truncate" title={log.source || ""}>
                      {log.source || "-"}
                    </td>
                    <td className="px-1.5 py-1 text-slate-600 font-mono text-[10px] max-w-0">
                      <div className="truncate whitespace-nowrap" title={log.interface_id || ""}>
                        <QuickFilterValue
                          onClick={
                            log.interface_id
                              ? () => onQuickFilter?.({ field: "interface_id", value: log.interface_id })
                              : null
                          }
                          title="Filter by interface"
                        >
                          {log.interface_id || "-"}
                        </QuickFilterValue>
                      </div>
                    </td>
                    <td className="px-1.5 py-1 text-slate-600 max-w-0">
                      <div className="truncate whitespace-nowrap" title={log.log_status || ""}>
                        {log.log_status || "-"}
                      </div>
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr key={`raw-${log.id}`} className="bg-neutral-50/70">
                      <td className="px-1.5 py-1" />
                      <td colSpan={11} className="px-1.5 py-1">
                        <div className="text-[11px] text-slate-500 mb-1">Raw Line</div>
                        <pre className="text-[11px] text-slate-700 bg-white border border-neutral-200 rounded p-2 overflow-auto max-h-28 font-mono whitespace-pre-wrap break-all">
                          {log.raw_line || "-"}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {logs.length === 0 && (
              <tr>
                <td colSpan={12} className="px-3 py-10 text-center text-slate-400">
                  {loading ? "Loading raw flows..." : "No raw flows found."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {(error || totalPages > 1) && (
        <div className="flex items-center justify-between px-4 py-2 border-t border-neutral-200 bg-neutral-50/50">
          <div className="text-xs text-danger min-h-4">{error || ""}</div>
          {totalPages > 1 && (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => onPageChange(page - 1)}
                disabled={loading || page <= 1}
                className="flex items-center gap-1 px-2 py-1 rounded text-xs text-slate-500 hover:text-slate-900 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <Icon name="chevron_left" size={16} />
                Previous
              </button>
              <span className="text-xs text-slate-500">
                Page {page} of {totalPages}
              </span>
              <button
                type="button"
                onClick={() => onPageChange(page + 1)}
                disabled={loading || page >= totalPages}
                className="flex items-center gap-1 px-2 py-1 rounded text-xs text-slate-500 hover:text-slate-900 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Next
                <Icon name="chevron_right" size={16} />
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
