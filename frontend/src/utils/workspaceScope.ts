const WORKSPACE_IDS_PREFIX = 'vulnguard_workspace_ids:';

export function getWorkspaceOwnerKey(sub?: string | null): string {
  return sub && sub.trim() ? sub.trim() : 'guest';
}

export function loadWorkspaceIds(ownerKey: string): string[] {
  if (typeof window === 'undefined' || !window.localStorage) return [];
  try {
    const raw = window.localStorage.getItem(`${WORKSPACE_IDS_PREFIX}${ownerKey}`);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return Array.from(new Set(parsed.filter((id): id is string => typeof id === 'string' && id.length > 0)));
  } catch {
    return [];
  }
}

export function saveWorkspaceIds(ownerKey: string, ids: string[]): string[] {
  const unique = Array.from(new Set(ids.filter((id) => typeof id === 'string' && id.length > 0)));
  if (typeof window !== 'undefined' && window.localStorage) {
    try {
      window.localStorage.setItem(`${WORKSPACE_IDS_PREFIX}${ownerKey}`, JSON.stringify(unique));
    } catch {
      // Ignore quota/storage errors in restricted browser modes
    }
  }
  return unique;
}
