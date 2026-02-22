"use client"

import Link from "next/link"
import { useParams } from "next/navigation"
import { useCallback, useEffect, useMemo, useState } from "react"
import { API_BASE, cpFetch } from "../../../lib/api"
import { formatAge, levelToPillClass, type HealthLevel } from "../../../lib/format"

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
  classification?: { level?: number; label?: string; confidence?: number }
  engagement_score?: { score?: number; band?: string }
  coherence_score?: number
  coherence_violations?: string[]
  techniques?: Array<{ technique_id?: string; technique_name?: string; count?: number }>
  canaries?: {
    total_hits?: number
    total_tokens?: number
    tokens?: Array<{ token?: string; hits?: number; first_seen?: string; last_seen?: string }>
  }
}

type TheaterSessionPayload = {
  session_id?: string
  source_ip?: string
  event_count?: number
  created_at?: string
  current_stage?: string
  kill_chain?: string[]
  timeline?: Array<{
    timestamp?: string
    service?: string
    action?: string
    stage?: string
  }>
  prediction?: {
    current_stage?: string
    predicted_stage?: string
    predicted_action?: string
    confidence?: number
  }
  recommendation?: {
    recommendation_id?: string
    context_key?: string
    recommended_lure_arm?: string
    predicted_stage?: string
    predicted_action?: string
    confidence?: number
    apply_allowed?: boolean
  }
  narrative?: {
    context_id?: string
    world_id?: string
    discovery_depth?: number
    touched_services?: string[]
  }
}

type TheaterReplayBundlePayload = {
  found?: boolean
  session_id?: string
  replay?: SessionReplayPayload
  theater_session?: TheaterSessionPayload | null
}

const safeDecode = (raw: string): string => {
  try {
    return decodeURIComponent(raw)
  } catch {
    return raw
  }
}

const REPLAY_AUTO_REFRESH_INTERVAL_MS = 15000

const downloadJsonFile = (filename: string, payload: unknown): void => {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" })
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = objectUrl
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(objectUrl)
}

export default function TheaterReplayPage() {
  const params = useParams<{ sessionId?: string | string[] }>()
  const rawSessionId = params?.sessionId
  const sessionId = useMemo(() => {
    const raw = Array.isArray(rawSessionId) ? rawSessionId[0] : rawSessionId ?? ""
    return safeDecode(String(raw))
  }, [rawSessionId])

  const [replay, setReplay] = useState<SessionReplayPayload | null>(null)
  const [theaterSession, setTheaterSession] = useState<TheaterSessionPayload | null>(null)
  const [loading, setLoading] = useState(false)
  const [errorMessage, setErrorMessage] = useState("")
  const [lastUpdatedAtMs, setLastUpdatedAtMs] = useState<number | null>(null)
  const [clockMs, setClockMs] = useState(() => Date.now())
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true)
  const [eventsLimit, setEventsLimit] = useState(500)
  const [searchTerm, setSearchTerm] = useState("")
  const [serviceFilter, setServiceFilter] = useState("all")
  const [operatorBusy, setOperatorBusy] = useState(false)
  const [operatorMessage, setOperatorMessage] = useState("")
  const [actor, setActor] = useState("operator")
  const [applyDurationSeconds, setApplyDurationSeconds] = useState(300)
  const [labelConfidence, setLabelConfidence] = useState(0.8)

  const loadReplay = useCallback(async () => {
    if (!sessionId) {
      return
    }
    setLoading(true)
    setErrorMessage("")
    try {
      const bundleUrl = `${API_BASE}/theater/sessions/${encodeURIComponent(sessionId)}/bundle?events_limit=${eventsLimit}`
      const response = await cpFetch(bundleUrl, { cache: "no-store" })
      if (!response.ok) {
        setReplay(null)
        setTheaterSession(null)
        setErrorMessage(`replay unavailable (${response.status})`)
        return
      }
      const payload = (await response.json()) as TheaterReplayBundlePayload
      setReplay(payload.replay ?? null)
      setTheaterSession(payload.theater_session ?? null)
      if (!payload.found) {
        setErrorMessage("replay unavailable (not found)")
        return
      }
      setLastUpdatedAtMs(Date.now())
    } catch {
      setReplay(null)
      setTheaterSession(null)
      setErrorMessage("replay unavailable (network)")
    } finally {
      setLoading(false)
    }
  }, [eventsLimit, sessionId])

  const applyRecommendedLure = useCallback(async () => {
    const recommendation = theaterSession?.recommendation
    if (!sessionId || !recommendation?.recommended_lure_arm) {
      return
    }
    setOperatorBusy(true)
    setOperatorMessage("")
    try {
      const response = await cpFetch(`${API_BASE}/theater/actions/apply-lure`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          recommendation_id: recommendation.recommendation_id ?? null,
          lure_arm: recommendation.recommended_lure_arm,
          context_key: recommendation.context_key ?? "generic:*",
          duration_seconds: Math.max(1, applyDurationSeconds),
          actor: actor.trim() || "operator",
        }),
      })
      if (!response.ok) {
        setOperatorMessage(`apply failed (${response.status})`)
        return
      }
      setOperatorMessage(`applied ${recommendation.recommended_lure_arm}`)
      await loadReplay()
    } catch {
      setOperatorMessage("apply failed (network)")
    } finally {
      setOperatorBusy(false)
    }
  }, [actor, applyDurationSeconds, loadReplay, sessionId, theaterSession?.recommendation])

  const labelSession = useCallback(
    async (label: string) => {
      if (!sessionId || !label) {
        return
      }
      setOperatorBusy(true)
      setOperatorMessage("")
      try {
        const response = await cpFetch(`${API_BASE}/theater/actions/label`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: sessionId,
            recommendation_id: theaterSession?.recommendation?.recommendation_id ?? null,
            label,
            confidence: Math.max(0, Math.min(1, labelConfidence)),
            actor: actor.trim() || "operator",
          }),
        })
        if (!response.ok) {
          setOperatorMessage(`label failed (${response.status})`)
          return
        }
        setOperatorMessage(`labeled ${label}`)
        await loadReplay()
      } catch {
        setOperatorMessage("label failed (network)")
      } finally {
        setOperatorBusy(false)
      }
    },
    [actor, labelConfidence, loadReplay, sessionId, theaterSession?.recommendation?.recommendation_id]
  )

  const exportReplayJson = useCallback(() => {
    if (!sessionId || !replay) {
      return
    }
    downloadJsonFile(`clownpeanuts-replay-${sessionId}.json`, replay)
    setOperatorMessage("replay json downloaded")
  }, [replay, sessionId])

  const exportTheaterJson = useCallback(() => {
    if (!sessionId || !theaterSession) {
      return
    }
    downloadJsonFile(`clownpeanuts-theater-${sessionId}.json`, theaterSession)
    setOperatorMessage("theater json downloaded")
  }, [sessionId, theaterSession])

  useEffect(() => {
    const timer = setInterval(() => {
      setClockMs(Date.now())
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    loadReplay().catch(() => undefined)
  }, [loadReplay])

  useEffect(() => {
    if (!autoRefreshEnabled || !sessionId) {
      return () => undefined
    }
    const timer = setInterval(() => {
      loadReplay().catch(() => undefined)
    }, REPLAY_AUTO_REFRESH_INTERVAL_MS)
    return () => clearInterval(timer)
  }, [autoRefreshEnabled, loadReplay, sessionId])

  const replayAgeMs = useMemo(
    () => (lastUpdatedAtMs === null ? null : Math.max(0, clockMs - lastUpdatedAtMs)),
    [clockMs, lastUpdatedAtMs]
  )
  const replayStatus = useMemo(() => {
    if (loading) {
      return { className: "warn", label: "REPLAY LOADING" }
    }
    if (errorMessage) {
      return { className: "down", label: "REPLAY DEGRADED" }
    }
    if (replay && replay.found === false) {
      return { className: "down", label: "SESSION NOT FOUND" }
    }
    return { className: "up", label: "REPLAY READY" }
  }, [errorMessage, loading, replay])
  const freshness = useMemo(() => {
    if (replayAgeMs === null) {
      return { level: "warn" as HealthLevel, label: "snapshot pending" }
    }
    if (replayAgeMs <= 15000) {
      return { level: "good" as HealthLevel, label: `snapshot ${formatAge(replayAgeMs)} ago` }
    }
    if (replayAgeMs <= 35000) {
      return { level: "warn" as HealthLevel, label: `snapshot lag ${formatAge(replayAgeMs)}` }
    }
    return { level: "bad" as HealthLevel, label: `snapshot stale ${formatAge(replayAgeMs)}` }
  }, [replayAgeMs])
  const normalizedSearch = useMemo(() => searchTerm.trim().toLowerCase(), [searchTerm])

  const replayEvents = useMemo(() => replay?.session?.events ?? [], [replay?.session?.events])
  const theaterTimeline = useMemo(() => theaterSession?.timeline ?? [], [theaterSession?.timeline])
  const serviceOptions = useMemo(() => {
    const names = new Set<string>()
    for (const event of replayEvents) {
      const service = String(event.service ?? "").trim().toLowerCase()
      if (service) {
        names.add(service)
      }
    }
    for (const event of theaterTimeline) {
      const service = String(event.service ?? "").trim().toLowerCase()
      if (service) {
        names.add(service)
      }
    }
    return ["all", ...Array.from(names).sort()]
  }, [replayEvents, theaterTimeline])
  const filteredReplayEvents = useMemo(() => {
    return replayEvents
      .filter((event) => {
        const service = String(event.service ?? "").toLowerCase()
        if (serviceFilter !== "all" && service !== serviceFilter) {
          return false
        }
        if (!normalizedSearch) {
          return true
        }
        const haystack = `${event.service ?? ""} ${event.action ?? ""} ${event.message ?? ""}`.toLowerCase()
        return haystack.includes(normalizedSearch)
      })
      .slice(-35)
      .reverse()
  }, [normalizedSearch, replayEvents, serviceFilter])
  const filteredTimeline = useMemo(() => {
    return theaterTimeline
      .filter((event) => {
        const service = String(event.service ?? "").toLowerCase()
        if (serviceFilter !== "all" && service !== serviceFilter) {
          return false
        }
        if (!normalizedSearch) {
          return true
        }
        const haystack = `${event.service ?? ""} ${event.action ?? ""} ${event.stage ?? ""}`.toLowerCase()
        return haystack.includes(normalizedSearch)
      })
      .slice(-35)
      .reverse()
  }, [normalizedSearch, serviceFilter, theaterTimeline])
  const stageCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const item of theaterTimeline) {
      const stage = String(item.stage ?? "").trim()
      if (!stage) {
        continue
      }
      counts.set(stage, (counts.get(stage) ?? 0) + 1)
    }
    return Array.from(counts.entries())
      .map(([stage, count]) => ({ stage, count }))
      .sort((left, right) => right.count - left.count)
      .slice(0, 8)
  }, [theaterTimeline])
  const techniques = useMemo(() => (replay?.techniques ?? []).slice(0, 10), [replay?.techniques])
  const canaryTokens = useMemo(() => (replay?.canaries?.tokens ?? []).slice(0, 6), [replay?.canaries?.tokens])

  return (
    <main className="cp-page">
      <header className="cp-hero">
        <div>
          <p className="cp-kicker">Adversary Theater</p>
          <h1>Session Replay Drilldown</h1>
          <p className="cp-subtitle">
            Full timeline and scoring view for <strong>{sessionId || "unknown session"}</strong>.
          </p>
        </div>
        <div className="cp-hero-status">
          <div className={`cp-badge ${replayStatus.className}`}>{replayStatus.label}</div>
          <div className="cp-health-strip">
            <span className={`cp-pill ${levelToPillClass(freshness.level)}`}>{freshness.label}</span>
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
            placeholder="action, stage, service"
          />
        </label>
        <label>
          Service Filter
          <select value={serviceFilter} onChange={(event) => setServiceFilter(event.target.value)}>
            {serviceOptions.map((service) => (
              <option key={`service-option-${service}`} value={service}>
                {service}
              </option>
            ))}
          </select>
        </label>
        <label>
          Events Limit
          <select value={String(eventsLimit)} onChange={(event) => setEventsLimit(Number(event.target.value) || 500)}>
            <option value="200">200</option>
            <option value="500">500</option>
            <option value="800">800</option>
            <option value="1200">1200</option>
          </select>
        </label>
        <label>
          Auto Refresh
          <select value={autoRefreshEnabled ? "on" : "off"} onChange={(event) => setAutoRefreshEnabled(event.target.value === "on")}>
            <option value="on">on</option>
            <option value="off">off</option>
          </select>
        </label>
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
            value={applyDurationSeconds}
            onChange={(event) => setApplyDurationSeconds(Number(event.target.value) || 300)}
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
        <div className="cp-controls-actions">
          <button type="button" onClick={() => loadReplay().catch(() => undefined)} disabled={loading}>
            refresh now
          </button>
          <button type="button" onClick={exportReplayJson} disabled={!replay}>
            download replay json
          </button>
          <button type="button" onClick={exportTheaterJson} disabled={!theaterSession}>
            download theater json
          </button>
          <button
            type="button"
            disabled={operatorBusy || !theaterSession?.recommendation?.recommended_lure_arm}
            onClick={() => {
              applyRecommendedLure().catch(() => undefined)
            }}
          >
            apply recommended lure
          </button>
          <button
            type="button"
            disabled={operatorBusy}
            onClick={() => {
              labelSession("high_value_actor").catch(() => undefined)
            }}
          >
            label high value
          </button>
          <button
            type="button"
            disabled={operatorBusy}
            onClick={() => {
              labelSession("false_positive").catch(() => undefined)
            }}
          >
            label false positive
          </button>
          <Link className="cp-link-pill" href="/theater">
            back to theater
          </Link>
          <Link className="cp-link-pill" href="/">
            main dashboard
          </Link>
          <span>{operatorMessage || errorMessage || `replay refreshed ${formatAge(replayAgeMs)} ago`}</span>
        </div>
      </section>

      <section className="cp-stats">
        <article>
          <h2>Classification</h2>
          <p>{replay?.classification?.label ?? "unknown"}</p>
          <span>confidence {replay?.classification?.confidence ?? 0}</span>
        </article>
        <article>
          <h2>Engagement</h2>
          <p>{replay?.engagement_score?.score ?? 0}</p>
          <span>band {replay?.engagement_score?.band ?? "low"}</span>
        </article>
        <article>
          <h2>Narrative Coherence</h2>
          <p>{replay?.coherence_score ?? 0}</p>
          <span>{(replay?.coherence_violations ?? []).length} violations</span>
        </article>
        <article>
          <h2>Canary Hits</h2>
          <p>{replay?.canaries?.total_hits ?? 0}</p>
          <span>{replay?.canaries?.total_tokens ?? 0} tokens</span>
        </article>
      </section>

      <section className="cp-grid cp-grid-primary">
        <article className="cp-card">
          <h3>Kill Chain Path</h3>
          <ul className="cp-list">
            {(theaterSession?.kill_chain ?? []).slice(0, 12).map((stage, index) => (
              <li key={`kill-chain-${stage}-${index}`}>
                <span>step {index + 1}</span>
                <strong>{stage}</strong>
              </li>
            ))}
          </ul>
          <p className="cp-note">
            current {theaterSession?.current_stage ?? "unknown"} {"->"} predicted{" "}
            {theaterSession?.prediction?.predicted_stage ?? "unknown"}
          </p>
        </article>

        <article className="cp-card">
          <h3>Stage Frequency</h3>
          <ul className="cp-list">
            {stageCounts.map((item) => (
              <li key={`stage-${item.stage}`}>
                <span>{item.stage}</span>
                <strong>{item.count}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cp-card">
          <h3>Narrative Context</h3>
          <ul className="cp-list cp-list-small">
            <li>
              <span>world id</span>
              <strong>{theaterSession?.narrative?.world_id ?? "unknown"}</strong>
            </li>
            <li>
              <span>context id</span>
              <strong>{theaterSession?.narrative?.context_id ?? "unknown"}</strong>
            </li>
            <li>
              <span>discovery depth</span>
              <strong>{theaterSession?.narrative?.discovery_depth ?? 0}</strong>
            </li>
          </ul>
          <p className="cp-note">services {(theaterSession?.narrative?.touched_services ?? []).join(", ") || "none"}</p>
        </article>
      </section>

      <section className="cp-theater-grid cp-theater-grid-secondary">
        <article className="cp-card">
          <h3>Replay Events</h3>
          <ul className="cp-feed">
            {filteredReplayEvents.map((event, index) => (
              <li key={`replay-event-${String(event.timestamp ?? "")}-${index}`}>
                <span>{event.service ?? "service"}</span>
                <strong>{event.action ?? "action"}</strong>
                <small>{event.timestamp ?? ""}</small>
              </li>
            ))}
          </ul>
          <p className="cp-note">{filteredReplayEvents.length} filtered events (latest window)</p>
        </article>

        <article className="cp-card">
          <h3>Theater Timeline</h3>
          <ul className="cp-feed">
            {filteredTimeline.map((event, index) => (
              <li key={`timeline-event-${String(event.timestamp ?? "")}-${index}`}>
                <span>{event.stage ?? "unknown"}</span>
                <strong>
                  {event.service ?? "service"}:{event.action ?? "action"}
                </strong>
                <small>{event.timestamp ?? ""}</small>
              </li>
            ))}
          </ul>
          <p className="cp-note">recommendation {theaterSession?.recommendation?.recommended_lure_arm ?? "unknown"}</p>
        </article>

        <article className="cp-card">
          <h3>Techniques and Canaries</h3>
          <ul className="cp-list cp-list-small">
            {techniques.map((item) => (
              <li key={`technique-${item.technique_id ?? "unknown"}`}>
                <span>
                  {item.technique_id ?? "unknown"} {item.technique_name ?? ""}
                </span>
                <strong>{item.count ?? 0}</strong>
              </li>
            ))}
          </ul>
          <ul className="cp-list cp-list-small">
            {canaryTokens.map((item) => (
              <li key={`canary-${item.token ?? "token"}`}>
                <span>{item.token ?? "token"}</span>
                <strong>{item.hits ?? 0}</strong>
              </li>
            ))}
          </ul>
        </article>
      </section>
    </main>
  )
}
