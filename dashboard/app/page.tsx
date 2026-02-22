"use client"

import { scaleLinear } from "d3-scale"
import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import {
  API_BASE,
  WS_BASE,
  apiWebSocketProtocols,
  cpFetch,
  ensureDashboardAuthSession,
  withApiTokenQuery,
  withQueryParams,
} from "./lib/api"
import { formatAge, levelToPillClass, type HealthLevel } from "./lib/format"

type StatusPayload = {
  services?: Array<{ name: string; running: boolean; ports?: number[] }>
  sessions?: { sessions?: number; events?: number; credential_events?: number; command_events?: number }
  network?: { warnings?: string[]; compliant?: boolean; violations?: string[]; applied_rules?: string[] }
  threat_intel?: {
    enabled?: boolean
    strategy?: string
    last_profile?: string
    rotation_interval_seconds?: number
    scheduler_running?: boolean
    last_signal?: { ssh?: number; web?: number; db?: number }
  }
}

type IntelPayload = {
  totals?: {
    sessions?: number
    events?: number
    engagement_score_avg?: number
    canary_hits?: number
    fingerprinted_sessions?: number
    avg_session_duration_seconds?: number
    mitre_coverage_percent?: number
  }
  techniques?: Array<{ technique_id: string; technique_name: string; count: number }>
  profiles?: Array<{ label: string; count: number }>
  fingerprints?: Array<{ tool: string; category: string; sessions: number; evidence_count: number }>
  kill_chain?: { stage_counts?: Array<{ stage: string; count: number }>; max_depth?: number; avg_depth?: number }
  kill_chain_graph?: { nodes?: Array<{ id: string; label: string; count: number }>; edges?: Array<{ source: string; target: string; count: number }> }
  geography?: {
    countries?: Array<{ country_code: string; country: string; sessions: number }>
    asns?: Array<{ asn: string; organization: string; sessions: number }>
  }
  biometrics?: {
    average_automation_score?: number
    automated_sessions?: number
    styles?: Array<{ style: string; count: number }>
  }
  coverage?: {
    catalog_size?: number
    observed_count?: number
    coverage_percent?: number
    gaps?: Array<{ technique_id: string; technique_name: string; tactic: string }>
  }
}

type MapPayload = {
  points?: Array<{ session_id: string; source_ip: string; lat: number; lon: number; event_count: number }>
  count?: number
  note?: string
}

type CanaryPayload = {
  tokens?: Array<{ token: string; hits: number; first_seen: string; last_seen: string }>
  total_tokens?: number
  total_hits?: number
}

type CanaryInventoryPayload = {
  tokens?: Array<{
    token_id: string
    token: string
    token_type: string
    namespace: string
    hit_count: number
    last_hit_at: string
  }>
  count?: number
}

type CanaryHitsPayload = {
  hits?: Array<{
    row_id: number
    token_id: string
    token: string
    source_ip: string
    service: string
    created_at: string
  }>
  count?: number
}

type CanaryTypesPayload = {
  types?: Array<{ token_type: string; description: string }>
  count?: number
}

type TemplateInventoryPayload = {
  enabled?: boolean
  template_count?: number
  services?: string[]
}

type TemplatePlanPayload = {
  tenant?: string
  count?: number
  services?: Array<{ name: string; enabled: boolean; ports: number[] }>
}

type TemplatePlanAllPayload = {
  all_tenants?: boolean
  tenant_count?: number
  count?: number
  plans?: Array<{ tenant: string; count: number }>
}

type TemplateValidationPayload = {
  ok?: boolean
  error_count?: number
  warning_count?: number
  files?: Array<{ path: string; template_count?: number; errors?: string[]; warnings?: string[] }>
}

type TemplateValidationAllPayload = {
  all_tenants?: boolean
  tenant_count?: number
  error_count?: number
  warning_count?: number
  tenants?: Array<{ tenant: string; ok: boolean; error_count: number; warning_count: number }>
}

type TemplateDiffPayload = {
  left_tenant?: string
  right_tenant?: string
  different?: boolean
  changed_count?: number
  left_only?: string[]
  right_only?: string[]
}

type TemplateDiffMatrixPayload = {
  comparison_count?: number
  different_count?: number
  all_same?: boolean
}

type ThreatPreviewPayload = {
  threat_intel?: {
    selected_profile?: string
    strategy?: string
    seasonal_profile?: string
    seasonal_month?: number
  }
}

type AlertPayload = {
  recent?: Array<{ timestamp: string; severity: string; title: string; summary: string; sent_to: string[] }>
}

type AlertRoutesPayload = {
  severity?: string
  deliver_count?: number
  blocked_count?: number
  routes?: Array<{ name: string; deliver: boolean; reason?: string }>
}

type DoctorPayload = {
  ok?: boolean
  checks?: Array<{ name: string; ok: boolean; detail: string }>
  templates?: { ok?: boolean; error_count?: number; warning_count?: number; tenant_count?: number }
  alerts?: {
    ok?: boolean
    enabled?: boolean
    enabled_destination_count?: number
    policy_destination_count?: number
    invalid_destinations?: Array<{ name: string }>
  }
}

type DashboardSummaryPayload = {
  status?: StatusPayload
  intel?: IntelPayload
  map?: MapPayload
  canaries?: CanaryPayload
  canary_inventory?: CanaryInventoryPayload
  canary_hits?: CanaryHitsPayload
  canary_types?: CanaryTypesPayload
  template_inventory?: TemplateInventoryPayload
  template_plan?: TemplatePlanPayload
  template_plan_all?: TemplatePlanAllPayload
  template_validation?: TemplateValidationPayload
  template_validation_all?: TemplateValidationAllPayload
  template_diff?: TemplateDiffPayload
  template_diff_matrix?: TemplateDiffMatrixPayload
  threat_preview?: ThreatPreviewPayload
  doctor?: DoctorPayload
  alerts?: AlertPayload
  alert_routes?: AlertRoutesPayload
  handoff?: HandoffPayload
}

type HandoffPayload = {
  generated_at?: string
  summary?: {
    sessions?: number
    events?: number
    canary_hits?: number
    engagement_score_avg?: number
    mitre_coverage_percent?: number
    top_kill_chain_stage?: string
    top_kill_chain_stage_count?: number
  }
  top_techniques?: Array<{ technique_id: string; technique_name: string; count: number }>
  priority_sessions?: Array<{
    session_id: string
    source_ip: string
    event_count: number
    engagement_score: number
    classification: string
  }>
  markdown?: string
  csv?: string
}

type LiveEvent = {
  event_id?: number
  topic?: string
  payload?: { service?: string; action?: string; message?: string; source_ip?: string; payload?: Record<string, unknown> }
}

type LiveEventBatch = {
  stream?: string
  cursor?: number
  events?: LiveEvent[]
}

type AnalystQueueItem = {
  id: string
  source: "alert" | "event"
  score: number
  severity: string
  service: string
  action: string
  title: string
  summary: string
  timestamp: string
}

export default function DashboardPage() {
  const [status, setStatus] = useState<StatusPayload>({})
  const [intel, setIntel] = useState<IntelPayload>({})
  const [alerts, setAlerts] = useState<AlertPayload>({})
  const [alertRoutes, setAlertRoutes] = useState<AlertRoutesPayload>({})
  const [map, setMap] = useState<MapPayload>({})
  const [canaries, setCanaries] = useState<CanaryPayload>({})
  const [canaryInventory, setCanaryInventory] = useState<CanaryInventoryPayload>({})
  const [canaryHits, setCanaryHits] = useState<CanaryHitsPayload>({})
  const [canaryTypes, setCanaryTypes] = useState<CanaryTypesPayload>({})
  const [templateInventory, setTemplateInventory] = useState<TemplateInventoryPayload>({})
  const [templatePlan, setTemplatePlan] = useState<TemplatePlanPayload>({})
  const [templatePlanAll, setTemplatePlanAll] = useState<TemplatePlanAllPayload>({})
  const [templateValidation, setTemplateValidation] = useState<TemplateValidationPayload>({})
  const [templateValidationAll, setTemplateValidationAll] = useState<TemplateValidationAllPayload>({})
  const [templateDiff, setTemplateDiff] = useState<TemplateDiffPayload>({})
  const [templateDiffMatrix, setTemplateDiffMatrix] = useState<TemplateDiffMatrixPayload>({})
  const [threatPreview, setThreatPreview] = useState<ThreatPreviewPayload>({})
  const [doctor, setDoctor] = useState<DoctorPayload>({})
  const [handoff, setHandoff] = useState<HandoffPayload>({})
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [streamRetryAttempt, setStreamRetryAttempt] = useState(0)
  const [streamRetryCountdownMs, setStreamRetryCountdownMs] = useState(0)
  const [lastEventAtMs, setLastEventAtMs] = useState<number | null>(null)
  const [lastSnapshotAtMs, setLastSnapshotAtMs] = useState<number | null>(null)
  const [clockMs, setClockMs] = useState(() => Date.now())
  const [searchTerm, setSearchTerm] = useState("")
  const [serviceFilter, setServiceFilter] = useState("all")
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("all")
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true)
  const [refreshIntervalMs, setRefreshIntervalMs] = useState(15000)
  const [routeSeverity, setRouteSeverity] = useState("medium")
  const [routeService, setRouteService] = useState("ops")
  const [routeAction, setRouteAction] = useState("alert_test")
  const [queueSourceFilter, setQueueSourceFilter] = useState("all")
  const [queueMinScore, setQueueMinScore] = useState(50)
  const [operatorBusy, setOperatorBusy] = useState(false)
  const [operatorMessage, setOperatorMessage] = useState("")
  const [handoffMessage, setHandoffMessage] = useState("")
  const streamCursorRef = useRef(0)

  const loadDashboard = useCallback(async () => {
    const params = new URLSearchParams({
      report_limit: "200",
      report_events_per_session: "200",
      map_limit: "200",
      map_events_per_session: "10",
      canary_limit: "8",
      include_templates: "false",
      include_doctor: "false",
      include_alert_routes: "true",
      route_severity: routeSeverity,
      route_service: routeService,
      route_action: routeAction,
    })
    const response = await cpFetch(`${API_BASE}/dashboard/summary?${params.toString()}`, { cache: "no-store" })
    if (!response.ok) {
      return
    }
    const payload = (await response.json()) as DashboardSummaryPayload
    setStatus(payload.status ?? {})
    setIntel(payload.intel ?? {})
    setMap(payload.map ?? {})
    setCanaries(payload.canaries ?? {})
    setCanaryInventory(payload.canary_inventory ?? {})
    setCanaryHits(payload.canary_hits ?? {})
    setCanaryTypes(payload.canary_types ?? {})
    if (payload.template_inventory !== undefined) setTemplateInventory(payload.template_inventory ?? {})
    if (payload.template_plan !== undefined) setTemplatePlan(payload.template_plan ?? {})
    if (payload.template_plan_all !== undefined) setTemplatePlanAll(payload.template_plan_all ?? {})
    if (payload.template_validation !== undefined) setTemplateValidation(payload.template_validation ?? {})
    if (payload.template_validation_all !== undefined) setTemplateValidationAll(payload.template_validation_all ?? {})
    if (payload.template_diff !== undefined) setTemplateDiff(payload.template_diff ?? {})
    if (payload.template_diff_matrix !== undefined) setTemplateDiffMatrix(payload.template_diff_matrix ?? {})
    if (payload.threat_preview !== undefined) setThreatPreview(payload.threat_preview ?? {})
    if (payload.doctor !== undefined) setDoctor(payload.doctor ?? {})
    setAlerts(payload.alerts ?? {})
    if (payload.alert_routes !== undefined) setAlertRoutes(payload.alert_routes ?? {})
    setLastSnapshotAtMs(Date.now())
  }, [routeAction, routeService, routeSeverity])

  const loadTemplateDiagnostics = useCallback(async () => {
    const params = new URLSearchParams({
      include_templates: "true",
      include_doctor: "true",
      include_alert_routes: "false",
      include_handoff: "true",
    })
    const response = await cpFetch(`${API_BASE}/dashboard/summary?${params.toString()}`, { cache: "no-store" })
    if (!response.ok) {
      return
    }
    const payload = (await response.json()) as DashboardSummaryPayload
    if (payload.template_inventory !== undefined) setTemplateInventory(payload.template_inventory ?? {})
    if (payload.template_plan !== undefined) setTemplatePlan(payload.template_plan ?? {})
    if (payload.template_plan_all !== undefined) setTemplatePlanAll(payload.template_plan_all ?? {})
    if (payload.template_validation !== undefined) setTemplateValidation(payload.template_validation ?? {})
    if (payload.template_validation_all !== undefined) setTemplateValidationAll(payload.template_validation_all ?? {})
    if (payload.template_diff !== undefined) setTemplateDiff(payload.template_diff ?? {})
    if (payload.template_diff_matrix !== undefined) setTemplateDiffMatrix(payload.template_diff_matrix ?? {})
    if (payload.doctor !== undefined) setDoctor(payload.doctor ?? {})
    if (payload.handoff !== undefined) setHandoff(payload.handoff ?? {})
  }, [])

  useEffect(() => {
    const timer = setInterval(() => {
      setClockMs(Date.now())
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    loadDashboard().catch(() => undefined)
    if (!autoRefreshEnabled) {
      return () => undefined
    }
    const timer = setInterval(() => {
      loadDashboard().catch(() => undefined)
    }, refreshIntervalMs)
    return () => clearInterval(timer)
  }, [autoRefreshEnabled, loadDashboard, refreshIntervalMs])

  useEffect(() => {
    loadTemplateDiagnostics().catch(() => undefined)
    if (!autoRefreshEnabled) {
      return () => undefined
    }
    const timer = setInterval(() => {
      loadTemplateDiagnostics().catch(() => undefined)
    }, 60000)
    return () => clearInterval(timer)
  }, [autoRefreshEnabled, loadTemplateDiagnostics])

  useEffect(() => {
    let closed = false
    let ws: WebSocket | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    let countdownTimer: ReturnType<typeof setInterval> | null = null
    let retryAttempt = 0

    const clearRetryTimers = () => {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer)
        reconnectTimer = null
      }
      if (countdownTimer) {
        clearInterval(countdownTimer)
        countdownTimer = null
      }
    }

    const scheduleReconnect = () => {
      if (closed) {
        return
      }
      retryAttempt += 1
      setStreamRetryAttempt(retryAttempt)
      const delayMs = Math.min(10000, 1000 * 2 ** Math.max(0, retryAttempt - 1))
      setStreamRetryCountdownMs(delayMs)
      countdownTimer = setInterval(() => {
        setStreamRetryCountdownMs((current) => (current <= 250 ? 0 : current - 250))
      }, 250)
      reconnectTimer = setTimeout(() => {
        clearRetryTimers()
        connect()
      }, delayMs)
    }

    const connect = () => {
      if (closed) {
        return
      }
      void ensureDashboardAuthSession().finally(() => {
        if (closed) {
          return
        }
        const wsUrl = withApiTokenQuery(
          withQueryParams(WS_BASE, {
            format: "batch",
            batch_limit: "160",
            interval_ms: "350",
            cursor: String(streamCursorRef.current),
          })
        )
        const protocols = apiWebSocketProtocols()
        ws = protocols.length > 0 ? new WebSocket(wsUrl, protocols) : new WebSocket(wsUrl)
        ws.onopen = () => {
          setConnected(true)
          retryAttempt = 0
          setStreamRetryAttempt(0)
          setStreamRetryCountdownMs(0)
          clearRetryTimers()
        }
        ws.onclose = () => {
          setConnected(false)
          if (!closed) {
            scheduleReconnect()
          }
        }
        ws.onerror = () => {
          if (ws && ws.readyState !== WebSocket.CLOSED) {
            ws.close()
          }
        }
        ws.onmessage = (event) => {
          try {
            const parsed = JSON.parse(event.data) as LiveEvent | LiveEventBatch
            const batchEvents =
              typeof parsed === "object" &&
              parsed !== null &&
              "stream" in parsed &&
              "events" in parsed &&
              parsed.stream === "events_batch" &&
              Array.isArray(parsed.events)
                ? (parsed.events as LiveEvent[])
                : null
            const batchCursor =
              typeof parsed === "object" &&
              parsed !== null &&
              "cursor" in parsed &&
              typeof parsed.cursor === "number" &&
              Number.isFinite(parsed.cursor)
                ? parsed.cursor
                : null
            const eventCursor =
              typeof parsed === "object" &&
              parsed !== null &&
              "event_id" in parsed &&
              typeof parsed.event_id === "number" &&
              Number.isFinite(parsed.event_id)
                ? parsed.event_id
                : null
            if (batchEvents) {
              if (batchEvents.length < 1) {
                return
              }
              if (batchCursor !== null && batchCursor > streamCursorRef.current) {
                streamCursorRef.current = Math.floor(batchCursor)
              }
              setLastEventAtMs(Date.now())
              const latestFirst = [...batchEvents].reverse()
              setEvents((current) => [...latestFirst, ...current].slice(0, 120))
              return
            }
            if (eventCursor !== null && eventCursor > streamCursorRef.current) {
              streamCursorRef.current = Math.floor(eventCursor)
            }
            setLastEventAtMs(Date.now())
            setEvents((current) => [parsed as LiveEvent, ...current].slice(0, 120))
          } catch {
            return
          }
        }
      })
    }

    connect()
    return () => {
      closed = true
      clearRetryTimers()
      if (ws && ws.readyState !== WebSocket.CLOSED) {
        ws.close()
      }
    }
  }, [])

  const runningServices = useMemo(() => (status.services ?? []).filter((service) => service.running).length, [status])
  const totalServices = useMemo(() => (status.services ?? []).length, [status])
  const serviceOptions = useMemo(
    () => ["all", ...(status.services ?? []).map((service) => service.name)],
    [status.services]
  )
  const profileRows = useMemo(() => (intel.profiles ?? []).slice(0, 6), [intel.profiles])
  const fingerprintRows = useMemo(() => (intel.fingerprints ?? []).slice(0, 8), [intel.fingerprints])
  const killChainRows = useMemo(() => (intel.kill_chain?.stage_counts ?? []).slice(0, 8), [intel.kill_chain])
  const killChainEdges = useMemo(() => (intel.kill_chain_graph?.edges ?? []).slice(0, 4), [intel.kill_chain_graph])
  const countryRows = useMemo(() => (intel.geography?.countries ?? []).slice(0, 4), [intel.geography])
  const asnRows = useMemo(() => (intel.geography?.asns ?? []).slice(0, 4), [intel.geography])
  const styleRows = useMemo(() => (intel.biometrics?.styles ?? []).slice(0, 4), [intel.biometrics])
  const coverageGaps = useMemo(() => (intel.coverage?.gaps ?? []).slice(0, 4), [intel.coverage])
  const mapPoints = map.points ?? []
  const canaryInventoryRows = useMemo(() => (canaryInventory.tokens ?? []).slice(0, 6), [canaryInventory.tokens])
  const canaryHitRows = useMemo(() => (canaryHits.hits ?? []).slice(0, 6), [canaryHits.hits])
  const canaryTypeRows = useMemo(() => (canaryTypes.types ?? []).slice(0, 6), [canaryTypes.types])
  const templatePlanRows = useMemo(() => (templatePlan.services ?? []).slice(0, 6), [templatePlan.services])
  const templatePlanTenantRows = useMemo(() => (templatePlanAll.plans ?? []).slice(0, 4), [templatePlanAll.plans])
  const templateValidationRows = useMemo(() => (templateValidation.files ?? []).slice(0, 4), [templateValidation.files])
  const templateValidationTenantRows = useMemo(
    () => (templateValidationAll.tenants ?? []).slice(0, 4),
    [templateValidationAll.tenants]
  )
  const handoffTechniqueRows = useMemo(() => (handoff.top_techniques ?? []).slice(0, 4), [handoff.top_techniques])
  const handoffSessionRows = useMemo(() => (handoff.priority_sessions ?? []).slice(0, 4), [handoff.priority_sessions])
  const handoffMarkdown = useMemo(() => String(handoff.markdown ?? "").trim(), [handoff.markdown])
  const handoffCsv = useMemo(() => String(handoff.csv ?? "").trim(), [handoff.csv])
  const alertRouteRows = useMemo(() => (alertRoutes.routes ?? []).slice(0, 4), [alertRoutes.routes])
  const doctorFailCount = useMemo(() => (doctor.checks ?? []).filter((item) => !item.ok).length, [doctor.checks])
  const normalizedSearch = useMemo(() => searchTerm.trim().toLowerCase(), [searchTerm])
  const filteredAlerts = useMemo(() => {
    const rows = alerts.recent ?? []
    return rows.filter((item) => {
      if (alertSeverityFilter !== "all" && item.severity !== alertSeverityFilter) {
        return false
      }
      if (!normalizedSearch) {
        return true
      }
      const haystack = `${item.title} ${item.summary} ${item.severity} ${(item.sent_to ?? []).join(" ")}`.toLowerCase()
      return haystack.includes(normalizedSearch)
    })
  }, [alertSeverityFilter, alerts.recent, normalizedSearch])
  const filteredEvents = useMemo(() => {
    return events.filter((event) => {
      const service = event.payload?.service ?? "core"
      if (serviceFilter !== "all" && service !== serviceFilter) {
        return false
      }
      if (!normalizedSearch) {
        return true
      }
      const haystack = `${service} ${event.payload?.action ?? ""} ${event.payload?.message ?? ""} ${event.payload?.source_ip ?? ""}`.toLowerCase()
      return haystack.includes(normalizedSearch)
    })
  }, [events, normalizedSearch, serviceFilter])
  const analystQueue = useMemo(() => {
    const severityWeights: Record<string, number> = { critical: 100, high: 80, medium: 55, low: 30 }
    const actionWeights: Record<string, number> = {
      credential_capture: 75,
      auth_attempt: 50,
      command: 42,
      command_attempt: 38,
    }

    const items: AnalystQueueItem[] = []
    for (const alert of alerts.recent ?? []) {
      const title = alert.title ?? "alert"
      const summary = alert.summary ?? ""
      const text = `${title} ${summary}`.toLowerCase()
      let score = severityWeights[alert.severity] ?? 35
      if (text.includes("credential")) score += 18
      if (text.includes("canary")) score += 14
      if (text.includes("pivot")) score += 12
      if (text.includes("lateral")) score += 10
      items.push({
        id: `alert-${alert.timestamp}-${title}`,
        source: "alert",
        score,
        severity: alert.severity,
        service: title.split(":")[0] || "ops",
        action: title.split(":")[1] || "alert",
        title,
        summary,
        timestamp: alert.timestamp,
      })
    }

    for (const [index, event] of events.entries()) {
      const service = event.payload?.service ?? "core"
      const action = event.payload?.action ?? "event"
      const message = event.payload?.message ?? ""
      const sourceIp = event.payload?.source_ip ?? ""
      const text = `${service} ${action} ${message} ${sourceIp}`.toLowerCase()
      let score = actionWeights[action] ?? 20
      if (text.includes("failed")) score += 8
      if (text.includes("credential")) score += 12
      if (sourceIp) score += 4
      score = Math.max(10, score - Math.min(index, 30))
      items.push({
        id: `event-${index}-${service}-${action}-${message}`,
        source: "event",
        score,
        severity: "info",
        service,
        action,
        title: `${service}:${action}`,
        summary: message || "live stream event",
        timestamp: "",
      })
    }

    return items
      .filter((item) => {
        if (queueSourceFilter !== "all" && item.source !== queueSourceFilter) return false
        if (serviceFilter !== "all" && item.service !== serviceFilter) return false
        if (item.score < queueMinScore) return false
        if (!normalizedSearch) return true
        const haystack = `${item.title} ${item.summary} ${item.service} ${item.action}`.toLowerCase()
        return haystack.includes(normalizedSearch)
      })
      .sort((left, right) => right.score - left.score)
      .slice(0, 10)
  }, [alerts.recent, events, normalizedSearch, queueMinScore, queueSourceFilter, serviceFilter])
  const eventAgeMs = useMemo(
    () => (lastEventAtMs === null ? null : Math.max(0, clockMs - lastEventAtMs)),
    [clockMs, lastEventAtMs]
  )
  const snapshotAgeMs = useMemo(
    () => (lastSnapshotAtMs === null ? null : Math.max(0, clockMs - lastSnapshotAtMs)),
    [clockMs, lastSnapshotAtMs]
  )
  const snapshotFreshness = useMemo(() => {
    if (snapshotAgeMs === null) {
      return { level: "warn" as HealthLevel, label: "snapshot pending" }
    }
    if (snapshotAgeMs <= refreshIntervalMs * 2) {
      return { level: "good" as HealthLevel, label: `snapshot ${formatAge(snapshotAgeMs)} ago` }
    }
    if (snapshotAgeMs <= Math.max(refreshIntervalMs * 3, 15000)) {
      return { level: "warn" as HealthLevel, label: `snapshot lag ${formatAge(snapshotAgeMs)}` }
    }
    return { level: "bad" as HealthLevel, label: `snapshot stale ${formatAge(snapshotAgeMs)}` }
  }, [refreshIntervalMs, snapshotAgeMs])
  const eventFreshness = useMemo(() => {
    if (!connected && streamRetryAttempt > 0) {
      return { level: "warn" as HealthLevel, label: "event stream reconnecting" }
    }
    if (!connected) {
      return { level: "bad" as HealthLevel, label: "event stream offline" }
    }
    if (eventAgeMs === null) {
      return { level: "warn" as HealthLevel, label: "connected, awaiting first event" }
    }
    if (eventAgeMs <= 120000) {
      return { level: "good" as HealthLevel, label: `last event ${formatAge(eventAgeMs)} ago` }
    }
    return { level: "warn" as HealthLevel, label: `event stream quiet ${formatAge(eventAgeMs)}` }
  }, [connected, eventAgeMs, streamRetryAttempt])
  const eventStreamBadge = useMemo(() => {
    if (connected) {
      return "EVENT STREAM LIVE"
    }
    if (streamRetryAttempt > 0) {
      const countdownSeconds = Math.max(1, Math.ceil(streamRetryCountdownMs / 1000))
      return `EVENT RECONNECT ${streamRetryAttempt} (${countdownSeconds}s)`
    }
    return "EVENT STREAM OFFLINE"
  }, [connected, streamRetryAttempt, streamRetryCountdownMs])
  const eventStreamClass = useMemo(() => {
    if (connected) {
      return "up"
    }
    if (streamRetryAttempt > 0) {
      return "warn"
    }
    return "down"
  }, [connected, streamRetryAttempt])

  const mapX = useMemo(() => scaleLinear().domain([-170, 170]).range([20, 580]), [])
  const mapY = useMemo(() => scaleLinear().domain([70, -70]).range([20, 260]), [])

  const focusQueueItem = (item: AnalystQueueItem) => {
    if (item.service) {
      setServiceFilter(item.service)
      setRouteService(item.service)
    }
    if (item.action) {
      setRouteAction(item.action)
    }
    if (item.severity === "low" || item.severity === "medium" || item.severity === "high" || item.severity === "critical") {
      setRouteSeverity(item.severity)
    }
  }

  const copyHandoffMarkdown = async () => {
    if (!handoffMarkdown) {
      setHandoffMessage("handoff markdown unavailable")
      return
    }
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(handoffMarkdown)
      } else if (typeof document !== "undefined") {
        const textArea = document.createElement("textarea")
        textArea.value = handoffMarkdown
        textArea.setAttribute("readonly", "true")
        textArea.style.position = "absolute"
        textArea.style.left = "-9999px"
        document.body.appendChild(textArea)
        textArea.select()
        document.execCommand("copy")
        document.body.removeChild(textArea)
      }
      setHandoffMessage("handoff markdown copied")
    } catch {
      setHandoffMessage("copy failed")
    }
  }

  const downloadHandoffMarkdown = () => {
    if (!handoffMarkdown || typeof document === "undefined") {
      setHandoffMessage("handoff markdown unavailable")
      return
    }
    const generatedAt = String(handoff.generated_at ?? new Date().toISOString())
      .replace(/[:.]/g, "-")
      .replace(/[^a-zA-Z0-9_-]/g, "")
    const filename = `clownpeanuts-handoff-${generatedAt || "latest"}.md`
    const blob = new Blob([`${handoffMarkdown}\n`], { type: "text/markdown;charset=utf-8" })
    const objectUrl = URL.createObjectURL(blob)
    const anchor = document.createElement("a")
    anchor.href = objectUrl
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
    URL.revokeObjectURL(objectUrl)
    setHandoffMessage(`downloaded ${filename}`)
  }

  const copyHandoffCsv = async () => {
    if (!handoffCsv) {
      setHandoffMessage("handoff csv unavailable")
      return
    }
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(handoffCsv)
      } else if (typeof document !== "undefined") {
        const textArea = document.createElement("textarea")
        textArea.value = handoffCsv
        textArea.setAttribute("readonly", "true")
        textArea.style.position = "absolute"
        textArea.style.left = "-9999px"
        document.body.appendChild(textArea)
        textArea.select()
        document.execCommand("copy")
        document.body.removeChild(textArea)
      }
      setHandoffMessage("handoff csv copied")
    } catch {
      setHandoffMessage("copy failed")
    }
  }

  const downloadHandoffCsv = () => {
    if (!handoffCsv || typeof document === "undefined") {
      setHandoffMessage("handoff csv unavailable")
      return
    }
    const generatedAt = String(handoff.generated_at ?? new Date().toISOString())
      .replace(/[:.]/g, "-")
      .replace(/[^a-zA-Z0-9_-]/g, "")
    const filename = `clownpeanuts-handoff-${generatedAt || "latest"}.csv`
    const blob = new Blob([`${handoffCsv}\n`], { type: "text/csv;charset=utf-8" })
    const objectUrl = URL.createObjectURL(blob)
    const anchor = document.createElement("a")
    anchor.href = objectUrl
    anchor.download = filename
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
    URL.revokeObjectURL(objectUrl)
    setHandoffMessage(`downloaded ${filename}`)
  }

  const runAlertTest = async () => {
    setOperatorBusy(true)
    setOperatorMessage("")
    try {
      const response = await cpFetch(`${API_BASE}/alerts/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          severity: routeSeverity,
          service: routeService,
          action: routeAction,
          title: "dashboard_operator_test",
          summary: "dashboard-triggered synthetic alert",
        }),
      })
      if (!response.ok) {
        setOperatorMessage(`alert test failed (${response.status})`)
      } else {
        setOperatorMessage("alert test sent")
        await loadDashboard()
      }
    } catch {
      setOperatorMessage("alert test failed (network)")
    } finally {
      setOperatorBusy(false)
    }
  }

  const runRotation = async () => {
    setOperatorBusy(true)
    setOperatorMessage("")
    try {
      const response = await cpFetch(`${API_BASE}/intel/rotate`, { method: "POST" })
      if (!response.ok) {
        setOperatorMessage(`rotation failed (${response.status})`)
      } else {
        setOperatorMessage("rotation triggered")
        await loadDashboard()
      }
    } catch {
      setOperatorMessage("rotation failed (network)")
    } finally {
      setOperatorBusy(false)
    }
  }

  return (
    <main className="cp-page">
      <header className="cp-hero">
        <div>
          <p className="cp-kicker">ClownPeanuts Operations</p>
          <h1>Adaptive Deception Control Plane</h1>
          <p className="cp-subtitle">Live engagement tracking, alert telemetry, and attacker intelligence in one view.</p>
        </div>
        <div className="cp-hero-status">
          <div className={`cp-badge ${eventStreamClass}`}>{eventStreamBadge}</div>
          <div className="cp-health-strip">
            <span className={`cp-pill ${levelToPillClass(eventFreshness.level)}`}>{eventFreshness.label}</span>
            <span className={`cp-pill ${levelToPillClass(snapshotFreshness.level)}`}>{snapshotFreshness.label}</span>
          </div>
        </div>
      </header>

      <section className="cp-controls">
        <label>
          Search
          <input
            type="text"
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            placeholder="service, action, source ip, alert title"
          />
        </label>
        <label>
          Event Service
          <select value={serviceFilter} onChange={(event) => setServiceFilter(event.target.value)}>
            {serviceOptions.map((service) => (
              <option key={`service-option-${service}`} value={service}>
                {service}
              </option>
            ))}
          </select>
        </label>
        <label>
          Alert Severity
          <select value={alertSeverityFilter} onChange={(event) => setAlertSeverityFilter(event.target.value)}>
            <option value="all">all</option>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </label>
        <label>
          Route Preview Severity
          <select value={routeSeverity} onChange={(event) => setRouteSeverity(event.target.value)}>
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
            <option value="critical">critical</option>
          </select>
        </label>
        <label>
          Route Preview Service
          <input type="text" value={routeService} onChange={(event) => setRouteService(event.target.value || "ops")} />
        </label>
        <label>
          Route Preview Action
          <input type="text" value={routeAction} onChange={(event) => setRouteAction(event.target.value || "alert_test")} />
        </label>
        <label>
          Queue Source
          <select value={queueSourceFilter} onChange={(event) => setQueueSourceFilter(event.target.value)}>
            <option value="all">all</option>
            <option value="alert">alerts</option>
            <option value="event">events</option>
          </select>
        </label>
        <label>
          Queue Min Score
          <input
            type="number"
            min={0}
            max={120}
            value={queueMinScore}
            onChange={(event) => setQueueMinScore(Number(event.target.value) || 0)}
          />
        </label>
        <label>
          Refresh
          <select
            value={String(refreshIntervalMs)}
            onChange={(event) => setRefreshIntervalMs(Number(event.target.value) || 15000)}
            disabled={!autoRefreshEnabled}
          >
            <option value="5000">5s</option>
            <option value="10000">10s</option>
            <option value="15000">15s</option>
            <option value="30000">30s</option>
          </select>
        </label>
        <div className="cp-controls-actions">
          <button type="button" onClick={() => setAutoRefreshEnabled((current) => !current)}>
            {autoRefreshEnabled ? "pause refresh" : "resume refresh"}
          </button>
          <button
            type="button"
            onClick={() => {
              loadDashboard().catch(() => undefined)
              loadTemplateDiagnostics().catch(() => undefined)
            }}
          >
            refresh now
          </button>
          <button type="button" onClick={runAlertTest} disabled={operatorBusy}>
            send alert test
          </button>
          <button type="button" onClick={runRotation} disabled={operatorBusy}>
            rotate bait now
          </button>
          <a className="cp-link-pill" href="/theater">
            open theater
          </a>
          <span>{operatorMessage}</span>
        </div>
      </section>

      <section className="cp-stats">
        <article>
          <h2>Service Health</h2>
          <p>{runningServices}</p>
          <span>of {totalServices} emulators running</span>
        </article>
        <article>
          <h2>Sessions</h2>
          <p>{status.sessions?.sessions ?? 0}</p>
          <span>{status.sessions?.events ?? 0} total events</span>
        </article>
        <article>
          <h2>Engagement</h2>
          <p>{intel.totals?.engagement_score_avg ?? 0}</p>
          <span>average intent score</span>
        </article>
        <article>
          <h2>Fingerprints</h2>
          <p>{intel.totals?.fingerprinted_sessions ?? 0}</p>
          <span>{fingerprintRows.length} active tool signatures</span>
        </article>
      </section>

      <section className="cp-grid cp-grid-primary">
        <article className="cp-card">
          <h3>Live Engagement Map</h3>
          <svg viewBox="0 0 600 280" role="img" aria-label="Engagement map">
            <rect x={0} y={0} width={600} height={280} rx={0} ry={0} className="cp-map-bg" />
            {mapPoints.map((point) => (
              <g key={point.session_id}>
                <circle cx={mapX(point.lon)} cy={mapY(point.lat)} r={Math.max(3, Math.min(12, point.event_count + 2))} className="cp-map-dot" />
              </g>
            ))}
          </svg>
          <p className="cp-note">{map.note ?? "No map points yet."}</p>
        </article>

        <article className="cp-card">
          <h3>Attacker Profiles</h3>
          <ul className="cp-list">
            {profileRows.map((item) => (
              <li key={item.label}>
                <span>{item.label}</span>
                <strong>{item.count}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Session Tempo</h3>
          <ul className="cp-list cp-list-small">
            {(intel.profiles ?? []).slice(0, 3).map((profile) => (
              <li key={profile.label}>
                <span>{profile.label}</span>
                <strong>{profile.count}</strong>
              </li>
            ))}
          </ul>
          <p className="cp-note">avg duration {intel.totals?.avg_session_duration_seconds ?? 0}s</p>
        </article>
      </section>

      <section className="cp-grid cp-grid-secondary">
        <article className="cp-card">
          <h3>ATT&CK Overview</h3>
          <ul className="cp-list">
            {(intel.techniques ?? []).slice(0, 10).map((item) => (
              <li key={item.technique_id}>
                <span>
                  {item.technique_id} {item.technique_name}
                </span>
                <strong>{item.count}</strong>
              </li>
            ))}
          </ul>
          <p className="cp-note">
            coverage {intel.coverage?.coverage_percent ?? intel.totals?.mitre_coverage_percent ?? 0}% (
            {intel.coverage?.observed_count ?? 0}/{intel.coverage?.catalog_size ?? 0})
          </p>
          <ul className="cp-list cp-list-small">
            {coverageGaps.map((item) => (
              <li key={item.technique_id}>
                <span>
                  gap {item.technique_id} {item.technique_name}
                </span>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Tool Fingerprints</h3>
          <ul className="cp-list">
            {fingerprintRows.map((item) => (
              <li key={item.tool}>
                <span>
                  {item.tool} ({item.category})
                </span>
                <strong>{item.sessions}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Kill Chain Progression</h3>
          <ul className="cp-list">
            {killChainRows.map((item) => (
              <li key={item.stage}>
                <span>{item.stage}</span>
                <strong>{item.count}</strong>
              </li>
            ))}
          </ul>
          <p className="cp-note">
            max depth {intel.kill_chain?.max_depth ?? 0}, avg depth {intel.kill_chain?.avg_depth ?? 0}
          </p>
          <ul className="cp-list cp-list-small">
            {killChainEdges.map((edge) => (
              <li key={`${edge.source}-${edge.target}`}>
                <span>
                  {edge.source} → {edge.target}
                </span>
                <strong>{edge.count}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Source Geography</h3>
          <ul className="cp-list">
            {countryRows.map((item) => (
              <li key={item.country_code}>
                <span>
                  {item.country_code} {item.country}
                </span>
                <strong>{item.sessions}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>ASN Distribution</h3>
          <ul className="cp-list">
            {asnRows.map((item) => (
              <li key={item.asn}>
                <span>{item.asn}</span>
                <strong>{item.sessions}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Behavioral Biometrics</h3>
          <ul className="cp-list">
            {styleRows.map((item) => (
              <li key={item.style}>
                <span>{item.style}</span>
                <strong>{item.count}</strong>
              </li>
            ))}
          </ul>
          <p className="cp-note">
            avg automation {intel.biometrics?.average_automation_score ?? 0}, automated sessions{" "}
            {intel.biometrics?.automated_sessions ?? 0}
          </p>
        </article>

        <article className="cp-card">
          <h3>Recent Alerts</h3>
          <ul className="cp-feed">
            {filteredAlerts.slice(0, 8).map((item, idx) => (
              <li key={`${item.timestamp}-${idx}`}>
                <span className={`cp-pill ${item.severity}`}>{item.severity}</span>
                <strong>{item.title}</strong>
                <small>{item.summary}</small>
              </li>
            ))}
          </ul>
          <p className="cp-note">{filteredAlerts.length} matching alerts</p>
        </article>

        <article className="cp-card">
          <h3>Service Runtime</h3>
          <ul className="cp-feed">
            {(status.services ?? []).map((service) => (
              <li key={service.name}>
                <span className={`cp-pill ${service.running ? "good" : "bad"}`}>{service.running ? "up" : "down"}</span>
                <strong>{service.name}</strong>
                <small>{(service.ports ?? []).join(",")}</small>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Threat Rotation</h3>
          <ul className="cp-list cp-list-small">
            <li>
              <span>strategy</span>
              <strong>{status.threat_intel?.strategy ?? "balanced"}</strong>
            </li>
            <li>
              <span>profile</span>
              <strong>{status.threat_intel?.last_profile ?? "balanced"}</strong>
            </li>
            <li>
              <span>scheduler</span>
              <strong>{status.threat_intel?.scheduler_running ? "running" : "idle"}</strong>
            </li>
            <li>
              <span>interval</span>
              <strong>{status.threat_intel?.rotation_interval_seconds ?? 0}s</strong>
            </li>
          </ul>
          <p className="cp-note">
            signal ssh:{status.threat_intel?.last_signal?.ssh ?? 0} web:{status.threat_intel?.last_signal?.web ?? 0} db:
            {status.threat_intel?.last_signal?.db ?? 0}
          </p>
          <p className="cp-note">
            preview {threatPreview.threat_intel?.selected_profile ?? "balanced"}
            {threatPreview.threat_intel?.strategy === "seasonal" && threatPreview.threat_intel?.seasonal_month
              ? ` (seasonal month ${threatPreview.threat_intel?.seasonal_month})`
              : ""}
          </p>
        </article>

        <article className="cp-card">
          <h3>Template Inventory</h3>
          <ul className="cp-list cp-list-small">
            {(templateInventory.services ?? []).slice(0, 6).map((service) => (
              <li key={service}>
                <span>{service}</span>
              </li>
            ))}
          </ul>
          <p className="cp-note">
            {templateInventory.template_count ?? 0} template entries ({templateInventory.enabled ? "enabled" : "disabled"})
          </p>
        </article>

        <article className="cp-card">
          <h3>Template Validation</h3>
          <p className={`cp-posture ${templateValidation.ok !== false ? "ok" : "risk"}`}>
            {templateValidation.ok !== false ? "Valid" : "Template Errors"}
          </p>
          <ul className="cp-list cp-list-small">
            {templateValidationRows.map((file) => (
              <li key={file.path}>
                <span>{file.path.split("/").slice(-1)[0]}</span>
                <strong>{file.template_count ?? 0}</strong>
              </li>
            ))}
          </ul>
          <p className="cp-note">
            {templateValidation.error_count ?? 0} errors, {templateValidation.warning_count ?? 0} warnings
          </p>
          <p className="cp-note">
            all tenants: {templateValidationAll.tenant_count ?? 0} checked, {templateValidationAll.error_count ?? 0} errors,{" "}
            {templateValidationAll.warning_count ?? 0} warnings
          </p>
          <ul className="cp-list cp-list-small">
            {templateValidationTenantRows.map((tenant) => (
              <li key={tenant.tenant}>
                <span>{tenant.tenant}</span>
                <strong>{tenant.ok ? "ok" : `${tenant.error_count} err / ${tenant.warning_count} warn`}</strong>
              </li>
            ))}
          </ul>
        </article>
      </section>

      <section className="cp-grid cp-grid-secondary">
        <article className="cp-card">
          <h3>SOC Handoff</h3>
          <div className="cp-action-row">
            <button type="button" onClick={() => void copyHandoffMarkdown()}>
              copy markdown
            </button>
            <button type="button" onClick={downloadHandoffMarkdown}>
              download markdown
            </button>
            <button type="button" onClick={() => void copyHandoffCsv()}>
              copy csv
            </button>
            <button type="button" onClick={downloadHandoffCsv}>
              download csv
            </button>
            <span className="cp-handoff-message">{handoffMessage}</span>
          </div>
          <p className="cp-note">generated {handoff.generated_at ?? "pending"}</p>
          <ul className="cp-list cp-list-small">
            <li>
              <span>sessions</span>
              <strong>{handoff.summary?.sessions ?? 0}</strong>
            </li>
            <li>
              <span>events</span>
              <strong>{handoff.summary?.events ?? 0}</strong>
            </li>
            <li>
              <span>coverage</span>
              <strong>{handoff.summary?.mitre_coverage_percent ?? 0}%</strong>
            </li>
            <li>
              <span>dominant stage</span>
              <strong>
                {handoff.summary?.top_kill_chain_stage ?? "none"} ({handoff.summary?.top_kill_chain_stage_count ?? 0})
              </strong>
            </li>
          </ul>
          <div className="cp-handoff-split">
            <div>
              <p className="cp-note">top techniques</p>
              <ul className="cp-list cp-list-small">
                {handoffTechniqueRows.length > 0 ? (
                  handoffTechniqueRows.map((item) => (
                    <li key={`${item.technique_id}-${item.technique_name}`}>
                      <span>
                        {item.technique_id} {item.technique_name}
                      </span>
                      <strong>{item.count}</strong>
                    </li>
                  ))
                ) : (
                  <li>
                    <span>none observed</span>
                  </li>
                )}
              </ul>
            </div>
            <div>
              <p className="cp-note">priority sessions</p>
              <ul className="cp-list cp-list-small">
                {handoffSessionRows.length > 0 ? (
                  handoffSessionRows.map((item) => (
                    <li key={item.session_id}>
                      <span>{item.source_ip || item.session_id}</span>
                      <strong>{item.classification}</strong>
                    </li>
                  ))
                ) : (
                  <li>
                    <span>none observed</span>
                  </li>
                )}
              </ul>
            </div>
          </div>
          <pre className="cp-handoff-markdown">{handoffMarkdown || "No handoff markdown available yet."}</pre>
        </article>

        <article className="cp-card">
          <h3>Analyst Queue</h3>
          <ul className="cp-queue">
            {analystQueue.map((item) => (
              <li key={item.id}>
                <div>
                  <span className="cp-score">{item.score}</span>
                  <strong>{item.title}</strong>
                  <small>{item.summary}</small>
                </div>
                <button type="button" onClick={() => focusQueueItem(item)}>
                  focus
                </button>
              </li>
            ))}
          </ul>
          <p className="cp-note">{analystQueue.length} queued items</p>
        </article>

        <article className="cp-card">
          <h3>Live Event Stream</h3>
          <ul className="cp-feed">
            {filteredEvents.slice(0, 12).map((event, index) => (
              <li key={`${event.topic ?? "event"}-${index}`}>
                <span>{event.payload?.service ?? "core"}</span>
                <strong>{event.payload?.action ?? "event"}</strong>
                <small>{event.payload?.message ?? "-"}</small>
              </li>
            ))}
          </ul>
          <p className="cp-note">{filteredEvents.length} matching events</p>
        </article>

        <article className="cp-card">
          <h3>Canary Status Board</h3>
          <ul className="cp-list cp-list-small">
            {(canaries.tokens ?? []).slice(0, 6).map((token) => (
              <li key={token.token}>
                <span>{token.token}</span>
                <strong>{token.hits}</strong>
              </li>
            ))}
          </ul>
          <p className="cp-note">{intel.totals?.canary_hits ?? 0} hits across {canaries.total_tokens ?? 0} tokens</p>
        </article>

        <article className="cp-card">
          <h3>Canary Inventory</h3>
          <ul className="cp-list cp-list-small">
            {canaryInventoryRows.map((token) => (
              <li key={token.token_id}>
                <span>
                  {token.token_type}:{token.namespace} #{token.token_id.slice(0, 8)}
                </span>
                <strong>{token.hit_count}</strong>
              </li>
            ))}
          </ul>
          <p className="cp-note">{canaryInventory.count ?? 0} persisted tokens</p>
        </article>

        <article className="cp-card">
          <h3>Canary Hit Ledger</h3>
          <ul className="cp-feed">
            {canaryHitRows.map((hit) => (
              <li key={hit.row_id}>
                <span>{hit.service}</span>
                <strong>{hit.source_ip}</strong>
                <small>{hit.token_id.slice(0, 10)}</small>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Canary Types</h3>
          <ul className="cp-list cp-list-small">
            {canaryTypeRows.map((row) => (
              <li key={row.token_type}>
                <span>{row.token_type}</span>
                <strong>{row.description}</strong>
              </li>
            ))}
          </ul>
          <p className="cp-note">{canaryTypes.count ?? 0} supported artifact modes</p>
        </article>

        <article className="cp-card">
          <h3>Isolation Posture</h3>
          <p className={`cp-posture ${status.network?.compliant ? "ok" : "risk"}`}>
            {status.network?.compliant ? "Compliant" : "Violations Detected"}
          </p>
          <ul className="cp-list cp-list-small">
            {(status.network?.violations ?? []).map((item, index) => (
              <li key={`violation-${index}`}>
                <span>{item}</span>
              </li>
            ))}
            {(status.network?.warnings ?? []).map((item, index) => (
              <li key={`warning-${index}`}>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Doctor Readiness</h3>
          <p className={`cp-posture ${doctor.ok !== false ? "ok" : "risk"}`}>
            {doctor.ok !== false ? "Healthy" : "Issues Detected"}
          </p>
          <p className="cp-note">
            {doctor.checks?.length ?? 0} checks, {doctorFailCount} failing
          </p>
          <p className="cp-note">
            template lint: {doctor.templates?.error_count ?? 0} errors, {doctor.templates?.warning_count ?? 0} warnings
          </p>
          <p className="cp-note">tenants scanned: {doctor.templates?.tenant_count ?? 0}</p>
          <p className="cp-note">
            alerts: {doctor.alerts?.enabled_destination_count ?? 0} enabled destinations,{" "}
            {(doctor.alerts?.invalid_destinations ?? []).length} invalid
          </p>
          <p className="cp-note">alert policy filters: {doctor.alerts?.policy_destination_count ?? 0}</p>
          <p className="cp-note">
            route preview ({alertRoutes.severity ?? "medium"}): {alertRoutes.deliver_count ?? 0} deliver,{" "}
            {alertRoutes.blocked_count ?? 0} blocked
          </p>
          <ul className="cp-list cp-list-small">
            {alertRouteRows.map((route) => (
              <li key={`route-${route.name}`}>
                <span>{route.name}</span>
                <strong>{route.deliver ? "deliver" : route.reason || "blocked"}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Template Plan Preview</h3>
          <ul className="cp-feed">
            {templatePlanRows.map((service) => (
              <li key={`plan-${service.name}`}>
                <span className={`cp-pill ${service.enabled ? "good" : "bad"}`}>{service.enabled ? "on" : "off"}</span>
                <strong>{service.name}</strong>
                <small>{(service.ports ?? []).join(",")}</small>
              </li>
            ))}
          </ul>
          <p className="cp-note">tenant {templatePlan.tenant ?? "default"}, {templatePlan.count ?? 0} planned services</p>
          <p className="cp-note">
            all tenants: {templatePlanAll.tenant_count ?? 0} plans, {templatePlanAll.count ?? 0} services total
          </p>
          <ul className="cp-list cp-list-small">
            {templatePlanTenantRows.map((plan) => (
              <li key={`plan-tenant-${plan.tenant}`}>
                <span>{plan.tenant}</span>
                <strong>{plan.count}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Tenant Plan Diff</h3>
          <p className={`cp-posture ${templateDiff.different ? "risk" : "ok"}`}>
            {templateDiff.different ? "Differences Detected" : "No Differences"}
          </p>
          <p className="cp-note">
            {templateDiff.left_tenant ?? "left"} vs {templateDiff.right_tenant ?? "right"} ({templateDiff.changed_count ?? 0} changed services)
          </p>
          <p className="cp-note">
            left-only {(templateDiff.left_only ?? []).length}, right-only {(templateDiff.right_only ?? []).length}
          </p>
          <p className="cp-note">
            matrix: {templateDiffMatrix.comparison_count ?? 0} comparisons, {templateDiffMatrix.different_count ?? 0} with differences
          </p>
        </article>
      </section>
    </main>
  )
}
