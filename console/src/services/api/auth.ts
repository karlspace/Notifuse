import { api } from './client'
import type { Workspace } from './workspace'

// Authentication types
export interface SignInRequest {
  email: string
}

export interface SignInResponse {
  message: string
  code?: string
}

export interface VerifyCodeRequest {
  email: string
  code: string
}

export interface VerifyResponse {
  token: string
}

export interface GetCurrentUserResponse {
  user: {
    id: string
    email: string
    timezone: string
    language: string
  }
  workspaces: Workspace[]
}

/**
 * Parse a ROOT_EMAIL setting into a list of non-empty emails. Entries may be
 * separated by commas, semicolons, or whitespace (mirrors the backend parser and
 * the tag input's separators). Case is preserved (matching is case-sensitive).
 */
export function parseRootEmails(setting?: string): string[] {
  if (!setting) {
    return []
  }
  return setting.split(/[\s,;]+/).filter(Boolean)
}

/**
 * Check if the given user is one of the configured root users.
 * ROOT_EMAIL may hold multiple comma/semicolon-separated emails.
 */
export function isRootUser(userEmail?: string): boolean {
  if (!userEmail) {
    return false
  }
  return parseRootEmails(window.ROOT_EMAIL).includes(userEmail)
}

export interface LogoutResponse {
  message: string
}

export interface UpdateLanguageResponse {
  message: string
}

export const authService = {
  signIn: (data: SignInRequest) => api.post<SignInResponse>('/api/user.signin', data),
  verifyCode: (data: VerifyCodeRequest) => api.post<VerifyResponse>('/api/user.verify', data),
  getCurrentUser: () => api.get<GetCurrentUserResponse>('/api/user.me'),
  logout: () => api.post<LogoutResponse>('/api/user.logout', {}),
  updateLanguage: (language: string) =>
    api.post<UpdateLanguageResponse>('/api/user.updateLanguage', { language })
}
