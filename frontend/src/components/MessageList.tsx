'use client'

import { Message } from './ChatInterface'
import { ErrorDisplay } from './ErrorDisplay'
import { Paperclip, AlertTriangle } from 'lucide-react'

interface MessageListProps {
  messages: Message[]
}

interface AttachmentScanResult {
  isSuspicious: boolean
  reason?: string
}

function scanAttachment(name: string, size: number): AttachmentScanResult {
  // Check for invisible/zero-width characters in filename
  const invisibleCharPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/
  if (invisibleCharPattern.test(name)) {
    return { isSuspicious: true, reason: 'Filename contains invisible characters' }
  }

  // Check for suspicious shell/executable patterns in filename
  const executablePattern = /\.(exe|bat|sh|cmd|ps1|vbs|js|jar|py|rb|php|pl|com|scr|msi|dll|so|dylib)$/i
  if (executablePattern.test(name)) {
    return { isSuspicious: true, reason: 'Suspicious executable file type' }
  }

  // Check for prompt injection patterns in filename
  const promptInjectionPattern = /ignore\s+(previous|prior|above|all)|system\s*prompt|you\s+are\s+(now|a)|act\s+as|jailbreak|disregard|forget\s+(all|previous)|new\s+instructions?|override\s+(instructions?|rules?)/i
  if (promptInjectionPattern.test(name)) {
    return { isSuspicious: true, reason: 'Filename contains prompt injection pattern' }
  }

  // Check for base64-encoded content in filename
  const base64Pattern = /^[A-Za-z0-9+/]{20,}={0,2}$/
  if (base64Pattern.test(name.replace(/\s/g, ''))) {
    return { isSuspicious: true, reason: 'Filename appears to be base64-encoded' }
  }

  // Check for leetspeak patterns in filename
  const leetspeakPattern = /[1!][gq][n][o0][r][e3]|[s$][y][s$][t][e3][m]|[p][r][o0][m][p][t]/i
  if (leetspeakPattern.test(name)) {
    return { isSuspicious: true, reason: 'Filename contains leetspeak pattern' }
  }

  // Check for suspiciously long filenames that might hide content
  if (name.length > 255) {
    return { isSuspicious: true, reason: 'Filename is suspiciously long' }
  }

  // Check for null bytes or control characters in filename
  const controlCharPattern = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/
  if (controlCharPattern.test(name)) {
    return { isSuspicious: true, reason: 'Filename contains control characters' }
  }

  // Check for binary content indicators based on file extension vs size anomalies
  const binaryExtensions = /\.(bin|dat|raw|img|iso|dmg|tar|gz|zip|rar|7z)$/i
  if (binaryExtensions.test(name)) {
    return { isSuspicious: true, reason: 'Binary file type not allowed' }
  }

  return { isSuspicious: false }
}

export function MessageList({ messages }: MessageListProps) {
  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-4">
      {messages.map((message) => (
        <div
          key={message.id}
          className={`fade-in-up flex ${
            message.role === 'user' ? 'justify-end' : 'justify-start'
          }`}
        >
          <div
            className={`flex w-full max-w-3xl gap-3 ${
              message.role === 'user' ? 'flex-row-reverse' : 'flex-row'
            }`}
          >
            <div
              className={`mt-1 flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-2xl ${
                message.role === 'user'
                  ? 'bg-slate-200 text-slate-900'
                  : 'bg-gradient-to-br from-blue-600 to-sky-400 text-white shadow-[0_8px_18px_rgba(37,99,235,0.2)]'
              }`}
            >
              {message.role === 'user' ? (
                <span className="text-xs font-semibold uppercase tracking-[0.18em]">You</span>
              ) : (
                <div className="h-3 w-3 rounded-full bg-white/95" />
              )}
            </div>

            <div className="min-w-0 flex-1">
              <div
                className={`overflow-hidden rounded-[24px] border px-5 py-4 shadow-[0_18px_50px_rgba(2,6,23,0.18)] ${
                  message.role === 'user'
                    ? 'border-slate-700 bg-slate-100 text-slate-900'
                    : 'border-slate-700 bg-slate-900 text-slate-100 shadow-[0_12px_30px_rgba(2,6,23,0.28)]'
                }`}
              >
              {message.attachments && message.attachments.length > 0 && (
                  <div className="mb-3 flex flex-wrap gap-2">
                  {message.attachments.map((attachment) => {
                    const scanResult = scanAttachment(attachment.name, attachment.size)
                    return (
                      <div
                        key={attachment.id}
                          className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm ${
                            scanResult.isSuspicious
                              ? 'border-red-400 bg-red-50 text-red-700'
                              : message.role === 'user'
                              ? 'border-slate-300 bg-white text-slate-700'
                              : 'border-slate-700 bg-slate-800 text-slate-300'
                          }`}
                      >
                          {scanResult.isSuspicious ? (
                            <>
                              <AlertTriangle className="h-4 w-4 opacity-70 text-red-500" />
                              <span className="max-w-[180px] truncate text-red-600" title={`Blocked: ${scanResult.reason}`}>
                                [Blocked attachment]
                              </span>
                              <span className="text-xs opacity-60 text-red-500">
                                ({scanResult.reason})
                              </span>
                            </>
                          ) : (
                            <>
                              <Paperclip className="h-4 w-4 opacity-70" />
                              <span className="max-w-[180px] truncate">{attachment.name}</span>
                              <span className="text-xs opacity-60">
                                ({formatFileSize(attachment.size)})
                              </span>
                            </>
                          )}
                      </div>
                    )
                  })}
                  </div>
              )}

              {message.error ? (
                <ErrorDisplay error={message.error} />
              ) : (
                  <div className="message-content text-sm sm:text-[15px]">{message.content}</div>
              )}
              </div>

              <div
                className={`mt-2 px-1 text-xs text-slate-500 ${
                  message.role === 'user' ? 'text-right' : 'text-left'
                }`}
              >
                {formatTime(message.timestamp)}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(date: Date): string {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}