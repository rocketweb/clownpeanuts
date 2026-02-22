export type HealthLevel = "good" | "warn" | "bad"

export const formatAge = (ageMs: number | null): string => {
  if (ageMs === null) {
    return "none yet"
  }
  if (ageMs < 1000) {
    return "<1s"
  }
  const seconds = Math.floor(ageMs / 1000)
  if (seconds < 60) {
    return `${seconds}s`
  }
  const minutes = Math.floor(seconds / 60)
  const remainderSeconds = seconds % 60
  if (minutes < 60) {
    return remainderSeconds > 0 ? `${minutes}m ${remainderSeconds}s` : `${minutes}m`
  }
  const hours = Math.floor(minutes / 60)
  const remainderMinutes = minutes % 60
  return remainderMinutes > 0 ? `${hours}h ${remainderMinutes}m` : `${hours}h`
}

export const levelToPillClass = (level: HealthLevel): string => {
  if (level === "good") {
    return "good"
  }
  if (level === "warn") {
    return "medium"
  }
  return "bad"
}
