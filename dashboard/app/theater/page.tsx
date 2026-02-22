"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import {
  API_BASE,
  WS_THEATER_BASE,
  apiWebSocketProtocols,
  cpFetch,
  ensureDashboardAuthSession,
  withApiTokenQuery,
} from "../lib/api"
import { formatAge, levelToPillClass, type HealthLevel } from "../lib/format"

type TheaterTimelineRow = {
  timestamp?: string
  service?: string
  action?: string
  stage?: string
}

type TheaterPrediction = {
  current_stage?: string
  predicted_stage?: string
  predicted_action?: string
  confidence?: number
}

type TheaterRecommendation = {
  recommendation_id?: string
  session_id?: string
  context_key?: string
  recommended_lure_arm?: string
  predicted_stage?: string
  predicted_action?: string
  confidence?: number
  prediction_confidence?: number
  apply_allowed?: boolean
  explanation?: {
    version?: string
    weights?: { kill_chain?: number; narrative?: number; bandit?: number }
    components?: {
      kill_chain_score?: number
      narrative_score?: number
      bandit_score?: number
      composite_score?: number
    }
    signals?: {
      kill_chain_depth?: number
      narrative_discovery_depth?: number
      bandit_reward_avg?: number
      bandit_exploration_ratio?: number
    }
    fallback?: {
      applied?: boolean
      reason?: string
      candidate_arm?: string
      selected_arm?: string
    }
  }
  queue_position?: number
}

type TheaterSession = {
  session_id?: string
  source_ip?: string
  event_count?: number
  current_stage?: string
  kill_chain?: string[]
  timeline?: TheaterTimelineRow[]
  prediction?: TheaterPrediction
  recommendation?: TheaterRecommendation
}

type TheaterLivePayload = {
  enabled?: boolean
  mode?: string
  count?: number
  sessions?: TheaterSession[]
  recommendations?: TheaterRecommendation[]
  bandit_metrics?: {
    reward_avg?: number
    exploration_ratio?: number
  }
  latency_ms?: number
  within_latency_budget?: boolean
}

type TheaterActionsPayload = {
  actions?: Array<{
    row_id?: number
    created_at?: string
    action_type?: string
    session_id?: string
    recommendation_id?: string
    actor?: string
    payload?: Record<string, unknown>
    metadata?: Record<string, unknown>
  }>
  count?: number
}

type SessionReplayPayload = {
  found?: boolean
  session_id?: string
  session?: {
    session_id?: string
    source_ip?: string
    event_count?: number
    events?: Array<{
      timestamp?: string
      service?: string
      action?: string
      message?: string
      payload?: Record<string, unknown>
    }>
  }
  classification?: { label?: string; confidence?: number }
  engagement_score?: { score?: number; band?: string }
  coherence_score?: number
  coherence_violations?: string[]
  techniques?: Array<{ technique_id?: string; technique_name?: string; count?: number }>
  canaries?: {
    total_hits?: number
    total_tokens?: number
    tokens?: Array<{ token?: string; hits?: number }>
  }
}

const BOOKMARK_STORAGE_KEY = "clownpeanuts.theater.bookmarks.v1"
const THEATER_FALLBACK_POLL_INTERVAL_MS = 15000
const THEATER_ACTIONS_REFRESH_INTERVAL_MS = 15000
const THEATER_STREAM_INTERVAL_MS = 1500

const STAGE_ORDER = [
  "reconnaissance",
  "initial_access",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "exfiltration",
  "execution",
]

export default function TheaterPage() {
  const [live, setLive] = useState<TheaterLivePayload>({})
  const [actions, setActions] = useState<TheaterActionsPayload>({})
  const [selectedSessionId, setSelectedSessionId] = useState("")
  const [connected, setConnected] = useState(false)
  const [streamRetryAttempt, setStreamRetryAttempt] = useState(0)
  const [streamRetryCountdownMs, setStreamRetryCountdownMs] = useState(0)
  const [lastLiveUpdateAtMs, setLastLiveUpdateAtMs] = useState<number | null>(null)
  const [lastActionUpdateAtMs, setLastActionUpdateAtMs] = useState<number | null>(null)
  const [lastReplayUpdateAtMs, setLastReplayUpdateAtMs] = useState<number | null>(null)
  const [sessionReplay, setSessionReplay] = useState<SessionReplayPayload | null>(null)
  const [sessionReplayLoading, setSessionReplayLoading] = useState(false)
  const [sessionReplayError, setSessionReplayError] = useState("")
  const [replayReloadNonce, setReplayReloadNonce] = useState(0)
  const [clockMs, setClockMs] = useState(() => Date.now())
  const [bookmarkedSessionIds, setBookmarkedSessionIds] = useState<string[]>([])
  const [bookmarkedOnly, setBookmarkedOnly] = useState(false)
  const [busy, setBusy] = useState(false)
  const [actor, setActor] = useState("operator")
  const [applyDuration, setApplyDuration] = useState(300)
  const [labelConfidence, setLabelConfidence] = useState(0.75)
  const [operatorMessage, setOperatorMessage] = useState("")

  const loadLive = useCallback(async () => {
    const response = await cpFetch(`${API_BASE}/theater/live?limit=120&events_per_session=250`, { cache: "no-store" })
    if (!response.ok) {
      return
    }
    const payload = (await response.json()) as TheaterLivePayload
    setLive(payload)
    setLastLiveUpdateAtMs(Date.now())
  }, [])

  const loadActions = useCallback(async () => {
    const response = await cpFetch(`${API_BASE}/theater/actions?limit=30`, { cache: "no-store" })
    if (!response.ok) {
      return
    }
    const payload = (await response.json()) as TheaterActionsPayload
    setActions(payload)
    setLastActionUpdateAtMs(Date.now())
  }, [])

  useEffect(() => {
    const timer = setInterval(() => {
      setClockMs(Date.now())
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(BOOKMARK_STORAGE_KEY)
      if (!raw) {
        return
      }
      const parsed = JSON.parse(raw)
      if (!Array.isArray(parsed)) {
        return
      }
      const normalized = parsed
        .map((item) => String(item ?? "").trim())
        .filter((item) => item.length > 0)
      setBookmarkedSessionIds(Array.from(new Set(normalized)).slice(0, 200))
    } catch {
      return
    }
  }, [])

  useEffect(() => {
    window.localStorage.setItem(BOOKMARK_STORAGE_KEY, JSON.stringify(bookmarkedSessionIds))
  }, [bookmarkedSessionIds])

  useEffect(() => {
    loadLive().catch(() => undefined)
    loadActions().catch(() => undefined)
    const timer = setInterval(() => {
      if (connected) {
        loadActions().catch(() => undefined)
        return
      }
      loadLive().catch(() => undefined)
      loadActions().catch(() => undefined)
    }, connected ? THEATER_ACTIONS_REFRESH_INTERVAL_MS : THEATER_FALLBACK_POLL_INTERVAL_MS)
    return () => clearInterval(timer)
  }, [connected, loadActions, loadLive])

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
          `${WS_THEATER_BASE}?limit=120&events_per_session=250&interval_ms=${THEATER_STREAM_INTERVAL_MS}`
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
            const parsed = JSON.parse(event.data) as { payload?: TheaterLivePayload }
            if (parsed.payload) {
              setLive(parsed.payload)
              setLastLiveUpdateAtMs(Date.now())
            }
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

  const sessions = useMemo(() => live.sessions ?? [], [live.sessions])
  const recommendations = useMemo(() => live.recommendations ?? [], [live.recommendations])
  const actionsRows = useMemo(() => actions.actions ?? [], [actions.actions])
  const bookmarkSet = useMemo(() => new Set(bookmarkedSessionIds), [bookmarkedSessionIds])
  const visibleSessions = useMemo(() => {
    if (!bookmarkedOnly) {
      return sessions
    }
    return sessions.filter((session) => {
      const sessionId = String(session.session_id ?? "")
      return bookmarkSet.has(sessionId)
    })
  }, [bookmarkSet, bookmarkedOnly, sessions])
  const visibleRecommendations = useMemo(() => {
    if (!bookmarkedOnly) {
      return recommendations
    }
    return recommendations.filter((item) => {
      const sessionId = String(item.session_id ?? "")
      return bookmarkSet.has(sessionId)
    })
  }, [bookmarkSet, bookmarkedOnly, recommendations])
  const livePayloadAgeMs = useMemo(
    () => (lastLiveUpdateAtMs === null ? null : Math.max(0, clockMs - lastLiveUpdateAtMs)),
    [clockMs, lastLiveUpdateAtMs]
  )
  const actionLedgerAgeMs = useMemo(
    () => (lastActionUpdateAtMs === null ? null : Math.max(0, clockMs - lastActionUpdateAtMs)),
    [clockMs, lastActionUpdateAtMs]
  )
  const liveFreshness = useMemo(() => {
    if (!connected && streamRetryAttempt > 0) {
      return { level: "warn" as HealthLevel, label: "live stream reconnecting" }
    }
    if (!connected) {
      return { level: "bad" as HealthLevel, label: "live stream offline" }
    }
    if (livePayloadAgeMs === null) {
      return { level: "warn" as HealthLevel, label: "connected, awaiting first payload" }
    }
    if (livePayloadAgeMs <= 8000) {
      return { level: "good" as HealthLevel, label: `payload ${formatAge(livePayloadAgeMs)} ago` }
    }
    if (livePayloadAgeMs <= 18000) {
      return { level: "warn" as HealthLevel, label: `payload lag ${formatAge(livePayloadAgeMs)}` }
    }
    return { level: "bad" as HealthLevel, label: `payload stale ${formatAge(livePayloadAgeMs)}` }
  }, [connected, livePayloadAgeMs, streamRetryAttempt])
  const actionFreshness = useMemo(() => {
    if (actionLedgerAgeMs === null) {
      return { level: "warn" as HealthLevel, label: "actions pending" }
    }
    if (actionLedgerAgeMs <= 14000) {
      return { level: "good" as HealthLevel, label: `actions ${formatAge(actionLedgerAgeMs)} ago` }
    }
    if (actionLedgerAgeMs <= 28000) {
      return { level: "warn" as HealthLevel, label: `actions lag ${formatAge(actionLedgerAgeMs)}` }
    }
    return { level: "bad" as HealthLevel, label: `actions stale ${formatAge(actionLedgerAgeMs)}` }
  }, [actionLedgerAgeMs])
  const streamBadge = useMemo(() => {
    if (connected) {
      return "THEATER STREAM LIVE"
    }
    if (streamRetryAttempt > 0) {
      const countdownSeconds = Math.max(1, Math.ceil(streamRetryCountdownMs / 1000))
      return `THEATER RECONNECT ${streamRetryAttempt} (${countdownSeconds}s)`
    }
    return "THEATER STREAM OFFLINE"
  }, [connected, streamRetryAttempt, streamRetryCountdownMs])
  const streamBadgeClass = useMemo(() => {
    if (connected) {
      return "up"
    }
    if (streamRetryAttempt > 0) {
      return "warn"
    }
    return "down"
  }, [connected, streamRetryAttempt])

  useEffect(() => {
    if (!visibleSessions.length) {
      setSelectedSessionId("")
      return
    }
    const existing = visibleSessions.some((item) => item.session_id === selectedSessionId)
    if (!existing) {
      setSelectedSessionId(String(visibleSessions[0].session_id ?? ""))
    }
  }, [selectedSessionId, visibleSessions])

  const selectedSession = useMemo(
    () => visibleSessions.find((item) => String(item.session_id ?? "") === selectedSessionId) ?? null,
    [selectedSessionId, visibleSessions]
  )

  const selectedTimeline = useMemo(() => (selectedSession?.timeline ?? []).slice(0, 40), [selectedSession?.timeline])
  const selectedRecommendation = useMemo(
    () =>
      selectedSession?.recommendation ??
      visibleRecommendations.find((item) => String(item.session_id ?? "") === selectedSessionId) ??
      null,
    [selectedSession?.recommendation, selectedSessionId, visibleRecommendations]
  )
  const replayAgeMs = useMemo(
    () => (lastReplayUpdateAtMs === null ? null : Math.max(0, clockMs - lastReplayUpdateAtMs)),
    [clockMs, lastReplayUpdateAtMs]
  )
  const replayTechniques = useMemo(() => (sessionReplay?.techniques ?? []).slice(0, 5), [sessionReplay?.techniques])
  const replayCanaryTokens = useMemo(() => (sessionReplay?.canaries?.tokens ?? []).slice(0, 3), [sessionReplay?.canaries?.tokens])
  const replayEvents = useMemo(
    () => (sessionReplay?.session?.events ?? []).slice(-10).reverse(),
    [sessionReplay?.session?.events]
  )
  const replayTechniqueSummary = useMemo(() => {
    if (!replayTechniques.length) {
      return "none observed"
    }
    return replayTechniques
      .map((item) => `${item.technique_id ?? "unknown"}:${item.count ?? 0}`)
      .join(", ")
  }, [replayTechniques])
  const replayCanarySummary = useMemo(() => {
    if (!replayCanaryTokens.length) {
      return "none observed"
    }
    return replayCanaryTokens
      .map((item) => `${item.token ?? "unknown"}:${item.hits ?? 0}`)
      .join(", ")
  }, [replayCanaryTokens])

  useEffect(() => {
    let closed = false
    const sessionId = selectedSessionId.trim()
    if (!sessionId) {
      setSessionReplay(null)
      setSessionReplayLoading(false)
      setSessionReplayError("")
      return () => {
        closed = true
      }
    }
    setSessionReplayLoading(true)
    setSessionReplayError("")

    const loadReplay = async () => {
      try {
        const response = await cpFetch(`${API_BASE}/sessions/${encodeURIComponent(sessionId)}/replay?events_limit=120`, {
          cache: "no-store",
        })
        if (!response.ok) {
          if (!closed) {
            setSessionReplay(null)
            setSessionReplayError(`session replay failed (${response.status})`)
          }
          return
        }
        const payload = (await response.json()) as SessionReplayPayload
        if (!closed) {
          setSessionReplay(payload)
          setLastReplayUpdateAtMs(Date.now())
        }
      } catch {
        if (!closed) {
          setSessionReplay(null)
          setSessionReplayError("session replay failed (network)")
        }
      } finally {
        if (!closed) {
          setSessionReplayLoading(false)
        }
      }
    }

    loadReplay().catch(() => undefined)
    return () => {
      closed = true
    }
  }, [replayReloadNonce, selectedSessionId])

  const graph = useMemo(() => {
    const stageCounts = new Map<string, number>()
    const edgeCounts = new Map<string, number>()

    for (const session of sessions) {
      const chain = session.kill_chain ?? []
      for (const stage of chain) {
        const key = String(stage)
        stageCounts.set(key, (stageCounts.get(key) ?? 0) + 1)
      }
      for (let index = 0; index < chain.length - 1; index += 1) {
        const source = String(chain[index])
        const target = String(chain[index + 1])
        if (!source || !target) {
          continue
        }
        const edgeKey = `${source}->${target}`
        edgeCounts.set(edgeKey, (edgeCounts.get(edgeKey) ?? 0) + 1)
      }
    }

    const nodes = STAGE_ORDER.map((stage, index) => {
      const count = stageCounts.get(stage) ?? 0
      const x = 70 + index * 105
      const y = index % 2 === 0 ? 72 : 118
      return { stage, count, x, y }
    })
    const edges: Array<{ source: string; target: string; count: number }> = []
    for (const [key, count] of edgeCounts.entries()) {
      const [source, target] = key.split("->")
      if (!source || !target) {
        continue
      }
      edges.push({ source, target, count })
    }
    return { nodes, edges }
  }, [sessions])

  const applyLure = useCallback(
    async (recommendation: TheaterRecommendation) => {
      const sessionId = String(recommendation.session_id ?? "")
      const recommendationId = String(recommendation.recommendation_id ?? "")
      const lureArm = String(recommendation.recommended_lure_arm ?? "")
      const contextKey = String(recommendation.context_key ?? "*")
      if (!sessionId || !lureArm) {
        return
      }
      setBusy(true)
      setOperatorMessage("")
      try {
        const response = await cpFetch(`${API_BASE}/theater/actions/apply-lure`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: sessionId,
            recommendation_id: recommendationId || null,
            lure_arm: lureArm,
            context_key: contextKey,
            duration_seconds: Math.max(1, applyDuration),
            actor: actor.trim() || "operator",
          }),
        })
        if (!response.ok) {
          setOperatorMessage(`apply failed (${response.status})`)
        } else {
          setOperatorMessage(`applied ${lureArm} to ${sessionId}`)
          await loadActions()
          await loadLive()
        }
      } catch {
        setOperatorMessage("apply failed (network)")
      } finally {
        setBusy(false)
      }
    },
    [actor, applyDuration, loadActions, loadLive]
  )

  const labelSession = useCallback(
    async (sessionId: string, label: string, recommendationId?: string) => {
      if (!sessionId || !label) {
        return
      }
      setBusy(true)
      setOperatorMessage("")
      try {
        const response = await cpFetch(`${API_BASE}/theater/actions/label`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: sessionId,
            recommendation_id: recommendationId || null,
            label,
            confidence: Math.max(0, Math.min(1, labelConfidence)),
            actor: actor.trim() || "operator",
          }),
        })
        if (!response.ok) {
          setOperatorMessage(`label failed (${response.status})`)
        } else {
          setOperatorMessage(`labeled ${sessionId} as ${label}`)
          await loadActions()
        }
      } catch {
        setOperatorMessage("label failed (network)")
      } finally {
        setBusy(false)
      }
    },
    [actor, labelConfidence, loadActions]
  )

  const toggleBookmark = useCallback((sessionId: string) => {
    const normalized = sessionId.trim()
    if (!normalized) {
      return
    }
    setBookmarkedSessionIds((current) => {
      if (current.includes(normalized)) {
        return current.filter((item) => item !== normalized)
      }
      return [normalized, ...current].slice(0, 200)
    })
  }, [])

  const selectedSessionBookmarked = selectedSessionId ? bookmarkSet.has(selectedSessionId) : false

  return (
    <main className="cp-page">
      <header className="cp-hero">
        <div>
          <p className="cp-kicker">Adversary Theater</p>
          <h1>Live Session Theater Console</h1>
          <p className="cp-subtitle">
            Timeline, kill-chain graph, recommendation queue, and operator action controls for active deception sessions.
          </p>
        </div>
        <div className="cp-hero-status">
          <div className={`cp-badge ${streamBadgeClass}`}>{streamBadge}</div>
          <div className="cp-health-strip">
            <span className={`cp-pill ${levelToPillClass(liveFreshness.level)}`}>{liveFreshness.label}</span>
            <span className={`cp-pill ${levelToPillClass(actionFreshness.level)}`}>{actionFreshness.label}</span>
          </div>
        </div>
      </header>

      <section className="cp-controls">
        <label>
          Actor
          <input type="text" value={actor} onChange={(event) => setActor(event.target.value)} />
        </label>
        <label>
          Apply Duration (s)
          <input
            type="number"
            min={1}
            max={3600}
            value={applyDuration}
            onChange={(event) => setApplyDuration(Number(event.target.value) || 300)}
          />
        </label>
        <label>
          Label Confidence
          <input
            type="number"
            min={0}
            max={1}
            step={0.01}
            value={labelConfidence}
            onChange={(event) => setLabelConfidence(Number(event.target.value))}
          />
        </label>
        <label>
          Bookmark Filter
          <select value={bookmarkedOnly ? "bookmarked" : "all"} onChange={(event) => setBookmarkedOnly(event.target.value === "bookmarked")}>
            <option value="all">all sessions</option>
            <option value="bookmarked">bookmarked only</option>
          </select>
        </label>
        <label>
          Selected Session
          <select value={selectedSessionId} onChange={(event) => setSelectedSessionId(event.target.value)} disabled={!visibleSessions.length}>
            {!visibleSessions.length ? (
              <option value="">no sessions</option>
            ) : null}
            {(visibleSessions ?? []).map((session) => {
              const sessionId = String(session.session_id ?? "")
              return (
                <option key={`session-option-${sessionId}`} value={sessionId}>
                  {sessionId} ({session.current_stage ?? "unknown"})
                </option>
              )
            })}
          </select>
        </label>
        <div className="cp-controls-actions">
          <button type="button" onClick={() => loadLive().catch(() => undefined)}>
            refresh live
          </button>
          <button type="button" onClick={() => loadActions().catch(() => undefined)}>
            refresh actions
          </button>
          <button type="button" onClick={() => toggleBookmark(selectedSessionId)} disabled={!selectedSessionId}>
            {selectedSessionBookmarked ? "remove bookmark" : "bookmark session"}
          </button>
          <button
            type="button"
            onClick={() => setReplayReloadNonce((current) => current + 1)}
            disabled={!selectedSessionId || sessionReplayLoading}
          >
            refresh replay
          </button>
          <a className="cp-link-pill" href="/">
            open main dashboard
          </a>
          <span>
            {sessionReplayLoading
              ? "loading replay..."
              : sessionReplayError
                ? sessionReplayError
                : `replay updated ${formatAge(replayAgeMs)} ago`}
          </span>
          <span>{bookmarkedSessionIds.length} bookmarked sessions</span>
          <span>{operatorMessage}</span>
        </div>
      </section>

      <section className="cp-stats">
        <article>
          <h2>Mode</h2>
          <p>{live.mode ?? "observe-only"}</p>
          <span>{live.enabled ? "enabled" : "disabled"}</span>
        </article>
        <article>
          <h2>Active Sessions</h2>
          <p>{live.count ?? 0}</p>
          <span>
            {visibleSessions.length} visible / {sessions.length} loaded
          </span>
        </article>
        <article>
          <h2>Recommendation Queue</h2>
          <p>{visibleRecommendations.length}</p>
          <span>{actions.count ?? 0} persisted actions</span>
        </article>
        <article>
          <h2>Latency Budget</h2>
          <p>{live.latency_ms ?? 0}ms</p>
          <span>{live.within_latency_budget ? "within 500ms budget" : "over 500ms budget"}</span>
        </article>
      </section>

      <section className="cp-theater-grid">
        <article className="cp-card">
          <h3>Kill Chain Graph</h3>
          <svg viewBox="0 0 900 190" role="img" aria-label="Kill-chain progression graph">
            <rect x={0} y={0} width={900} height={190} rx={0} ry={0} className="cp-map-bg" />
            {graph.edges.map((edge) => {
              const source = graph.nodes.find((node) => node.stage === edge.source)
              const target = graph.nodes.find((node) => node.stage === edge.target)
              if (!source || !target) {
                return null
              }
              return (
                <g key={`edge-${edge.source}-${edge.target}`}>
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    stroke="rgba(31, 75, 191, 0.46)"
                    strokeWidth={Math.max(1, Math.min(6, edge.count))}
                  />
                </g>
              )
            })}
            {graph.nodes.map((node) => (
              <g key={`node-${node.stage}`}>
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={Math.max(10, Math.min(22, 10 + node.count * 2))}
                  fill="#ffffff"
                  stroke="rgba(239, 59, 58, 0.82)"
                  strokeWidth={1.2}
                />
                <text x={node.x} y={node.y + 4} textAnchor="middle" fill="#152148" fontSize="9">
                  {node.count}
                </text>
                <text x={node.x} y={node.y + 33} textAnchor="middle" fill="#596178" fontSize="9">
                  {node.stage.replace("_", " ")}
                </text>
              </g>
            ))}
          </svg>
          <p className="cp-note">
            bandit reward {live.bandit_metrics?.reward_avg ?? 0} / exploration {live.bandit_metrics?.exploration_ratio ?? 0}
          </p>
        </article>

        <article className="cp-card">
          <h3>Session Timeline</h3>
          <ul className="cp-feed">
            {selectedTimeline.map((event, index) => (
              <li key={`timeline-${String(event.timestamp ?? "")}-${index}`}>
                <span>{event.stage ?? "unknown"}</span>
                <strong>{event.service ?? "service"}:{event.action ?? "action"}</strong>
                <small>{event.timestamp ?? ""}</small>
              </li>
            ))}
          </ul>
          <p className="cp-note">
            {selectedSession ? `${selectedSession.event_count ?? 0} events for ${selectedSession.session_id}` : "no session selected"}
          </p>
        </article>

        <article className="cp-card">
          <h3>Predicted Next Action</h3>
          {selectedSession ? (
            <>
              <p className="cp-posture ok">{selectedSession.prediction?.predicted_stage ?? "unknown"}</p>
              <ul className="cp-list cp-list-small">
                <li>
                  <span>current stage</span>
                  <strong>{selectedSession.prediction?.current_stage ?? "unknown"}</strong>
                </li>
                <li>
                  <span>predicted action</span>
                  <strong>{selectedSession.prediction?.predicted_action ?? "unknown"}</strong>
                </li>
                <li>
                  <span>prediction confidence</span>
                  <strong>{selectedSession.prediction?.confidence ?? 0}</strong>
                </li>
                <li>
                  <span>recommendation confidence</span>
                  <strong>{selectedRecommendation?.confidence ?? 0}</strong>
                </li>
              </ul>
            </>
          ) : (
            <p className="cp-note">no prediction available</p>
          )}
        </article>
      </section>

      <section className="cp-theater-grid cp-theater-grid-secondary">
        <article className="cp-card">
          <h3>Recommendation Queue</h3>
          <ul className="cp-queue">
            {visibleRecommendations.slice(0, 12).map((item) => {
              const recommendationId = String(item.recommendation_id ?? "")
              const sessionId = String(item.session_id ?? "")
              const fallbackApplied = Boolean(item.explanation?.fallback?.applied)
              const bookmarked = bookmarkSet.has(sessionId)
              return (
                <li key={`rec-${recommendationId}`}>
                  <div>
                    <span className="cp-score">
                      q{item.queue_position ?? 0} score {item.confidence ?? 0}
                    </span>
                    <strong>{sessionId} → {item.recommended_lure_arm ?? "generic-baseline"}</strong>
                    <small>
                      {item.predicted_stage ?? "unknown"} / {item.predicted_action ?? "unknown"}
                      {fallbackApplied ? ` fallback:${item.explanation?.fallback?.reason ?? "yes"}` : ""}
                    </small>
                  </div>
                  <div className="cp-action-row">
                    <button type="button" onClick={() => setSelectedSessionId(sessionId)}>
                      inspect
                    </button>
                    <a href={`/theater/replay/${encodeURIComponent(sessionId)}`}>drilldown</a>
                    <button type="button" onClick={() => toggleBookmark(sessionId)}>
                      {bookmarked ? "unbookmark" : "bookmark"}
                    </button>
                    <button
                      type="button"
                      disabled={busy || !item.apply_allowed}
                      onClick={() => {
                        applyLure(item).catch(() => undefined)
                      }}
                    >
                      apply
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => {
                        labelSession(sessionId, "high_value_actor", recommendationId).catch(() => undefined)
                      }}
                    >
                      label
                    </button>
                  </div>
                </li>
              )
            })}
          </ul>
          {!visibleRecommendations.length ? <p className="cp-note">no recommendations for current filter.</p> : null}
        </article>

        <article className="cp-card">
          <h3>Recommendation Explainability</h3>
          {selectedRecommendation ? (
            <>
              <ul className="cp-list cp-list-small">
                <li>
                  <span>weights</span>
                  <strong>
                    kc:{selectedRecommendation.explanation?.weights?.kill_chain ?? 0} nar:
                    {selectedRecommendation.explanation?.weights?.narrative ?? 0} band:
                    {selectedRecommendation.explanation?.weights?.bandit ?? 0}
                  </strong>
                </li>
                <li>
                  <span>components</span>
                  <strong>
                    kc:{selectedRecommendation.explanation?.components?.kill_chain_score ?? 0} nar:
                    {selectedRecommendation.explanation?.components?.narrative_score ?? 0} band:
                    {selectedRecommendation.explanation?.components?.bandit_score ?? 0}
                  </strong>
                </li>
                <li>
                  <span>composite</span>
                  <strong>{selectedRecommendation.explanation?.components?.composite_score ?? 0}</strong>
                </li>
                <li>
                  <span>fallback</span>
                  <strong>
                    {selectedRecommendation.explanation?.fallback?.applied
                      ? selectedRecommendation.explanation?.fallback?.reason ?? "applied"
                      : "none"}
                  </strong>
                </li>
              </ul>
              <p className="cp-note">
                kill chain depth {selectedRecommendation.explanation?.signals?.kill_chain_depth ?? 0}, discovery depth{" "}
                {selectedRecommendation.explanation?.signals?.narrative_discovery_depth ?? 0}
              </p>
            </>
          ) : (
            <p className="cp-note">select a recommendation to inspect explainability.</p>
          )}
        </article>

        <article className="cp-card">
          <h3>Session Replay Analyzer</h3>
          {selectedSessionId ? (
            <>
              <ul className="cp-list cp-list-small">
                <li>
                  <span>classification</span>
                  <strong>{sessionReplay?.classification?.label ?? "unknown"}</strong>
                </li>
                <li>
                  <span>engagement</span>
                  <strong>
                    {sessionReplay?.engagement_score?.score ?? 0} ({sessionReplay?.engagement_score?.band ?? "low"})
                  </strong>
                </li>
                <li>
                  <span>coherence</span>
                  <strong>{sessionReplay?.coherence_score ?? 0}</strong>
                </li>
                <li>
                  <span>events</span>
                  <strong>{sessionReplay?.session?.event_count ?? 0}</strong>
                </li>
              </ul>
              {sessionReplayLoading ? <p className="cp-note">loading replay snapshot...</p> : null}
              {sessionReplayError ? <p className="cp-note">{sessionReplayError}</p> : null}
              <ul className="cp-feed">
                {replayEvents.map((event, index) => (
                  <li key={`replay-${String(event.timestamp ?? "")}-${index}`}>
                    <span>{event.service ?? "service"}</span>
                    <strong>{event.action ?? "action"}</strong>
                    <small>{event.timestamp ?? ""}</small>
                  </li>
                ))}
              </ul>
              <p className="cp-note">techniques {replayTechniqueSummary}</p>
              <p className="cp-note">canaries {replayCanarySummary}</p>
              <p className="cp-note">
                replay refreshed {formatAge(replayAgeMs)} ago, violations {(sessionReplay?.coherence_violations ?? []).length}
              </p>
              <button className="cp-link-pill cp-link-pill-button" type="button" onClick={() => toggleBookmark(selectedSessionId)}>
                {selectedSessionBookmarked ? "remove bookmark" : "bookmark selected"}
              </button>
              <a className="cp-link-pill" href={`/theater/replay/${encodeURIComponent(selectedSessionId)}`}>
                open full replay
              </a>
            </>
          ) : (
            <p className="cp-note">select a live session to load replay telemetry.</p>
          )}
        </article>

        <article className="cp-card">
          <h3>Operator Action Ledger</h3>
          <ul className="cp-feed">
            {actionsRows.slice(0, 14).map((row) => (
              <li key={`action-${row.row_id ?? 0}`}>
                <span>{row.action_type ?? "action"}</span>
                <strong>{row.session_id ?? "session"}</strong>
                <small>
                  {(row.actor ?? "operator")} {row.created_at ?? ""}
                </small>
              </li>
            ))}
          </ul>
          <p className="cp-note">{actions.count ?? 0} recorded actions</p>
        </article>
      </section>
    </main>
  )
}
