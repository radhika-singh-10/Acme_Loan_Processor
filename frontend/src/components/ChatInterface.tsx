'use client'

import { useState, useRef, useEffect } from 'react'
import { v4 as uuidv4 } from 'uuid'
import { MessageList } from './MessageList'
import { FileUpload } from './FileUpload'
import { ArrowUp, Loader2, Paperclip, Plus } from 'lucide-react'

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  attachments?: FileAttachment[]
  error?: PolicyError
}

export interface FileAttachment {
  id: string
  name: string
  type: string
  size: number
  content?: string
}

export interface PolicyError {
  type: 'pii' | 'threat' | 'auth' | 'general'
  message: string
  details?: Record<string, unknown>
}

// --- Security utility functions ---

const MAX_INPUT_LENGTH = 10000
const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10 MB
const ALLOWED_MIME_TYPES = [
  'text/plain',
  'text/csv',
  'text/html',
  'text/markdown',
  'application/json',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
]

function sanitizeInput(input: string): string {
  // Trim whitespace
  let sanitized = input.trim()
  // Enforce max length
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH)
  }
  // Remove null bytes and dangerous control characters (keep newlines/tabs)
  sanitized = sanitized.replace(/\0/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  return sanitized
}

function sanitizeFileContent(content: string): string {
  // Strip null bytes and non-printable control characters (keep newlines/tabs)
  return content.replace(/\0/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
}

function validateFile(file: File): string | null {
  if (!ALLOWED_MIME_TYPES.includes(file.type)) {
    return `File type "${file.type}" is not allowed.`
  }
  if (file.size > MAX_FILE_SIZE) {
    return `File "${file.name}" exceeds the maximum allowed size of 10 MB.`
  }
  return null
}

// Instruction 1: Sanitize LLM output for dynamic code execution primitives
const DANGEROUS_CODE_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /new\s+Function\s*\(/gi,
  /setTimeout\s*\(\s*["'`]/gi,
  /setInterval\s*\(\s*["'`]/gi,
  /\bimportScripts\s*\(/gi,
  /document\.write\s*\(/gi,
  /innerHTML\s*=/gi,
  /outerHTML\s*=/gi,
  /\bexecScript\s*\(/gi,
  /\bsetImmediate\s*\(\s*["'`]/gi,
  /__import__\s*\(/gi,
  /\bcompile\s*\(/gi,
  /\bos\.system\s*\(/gi,
  /\bsubprocess\./gi,
]

function sanitizeLLMOutput(content: string): string {
  let sanitized = content
  let flagged = false
  for (const pattern of DANGEROUS_CODE_PATTERNS) {
    if (pattern.test(sanitized)) {
      flagged = true
      sanitized = sanitized.replace(pattern, '[REDACTED_CODE_PRIMITIVE]')
    }
  }
  if (flagged) {
    sanitized =
      '[Warning: Potentially dangerous code patterns were detected and removed from this response.]\n\n' +
      sanitized
  }
  return sanitized
}

// Instruction 3: Detect malicious prompts in file content
const MALICIOUS_PROMPT_PATTERNS = [
  // Prompt injection patterns
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
  /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
  /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
  /you\s+are\s+now\s+(a\s+)?(different|new|another)/gi,
  /act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?/gi,
  /pretend\s+(you\s+are|to\s+be)/gi,
  /new\s+instructions?:/gi,
  /system\s*:\s*(you|your)/gi,
  /\[system\]/gi,
  /\[assistant\]/gi,
  /\[user\]/gi,
  // Hidden/invisible text patterns (zero-width characters)
  /[\u200B-\u200D\uFEFF\u00AD]/g,
  // Shell/binary command patterns
  /\b(bash|sh|cmd|powershell|exec|system|popen|subprocess)\s*[\(\[]/gi,
  /\brm\s+-rf\b/gi,
  /\bchmod\s+[0-7]{3,4}\b/gi,
  /\bcurl\s+https?:\/\//gi,
  /\bwget\s+https?:\/\//gi,
  // Base64-encoded prompt injection (common patterns)
  /aWdub3Jl/gi, // "ignore" in base64
  /cHJldGVuZA==/gi, // "pretend" in base64
  /Zm9yZ2V0/gi, // "forget" in base64
  // Leetspeak injection patterns
  /1gn0r3\s+(4ll\s+)?(pr3v10us|pr10r)/gi,
  /d1sr3g4rd/gi,
]

function inspectFileContentForMaliciousPrompts(content: string, fileName: string): void {
  for (const pattern of MALICIOUS_PROMPT_PATTERNS) {
    if (pattern.test(content)) {
      throw new Error(
        `File "${fileName}" contains potentially malicious content or prompt injection patterns and cannot be uploaded.`
      )
    }
  }
  // Check for suspicious base64 blocks that decode to injection patterns
  const base64Blocks = content.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || []
  for (const block of base64Blocks) {
    try {
      const decoded = atob(block)
      const lowerDecoded = decoded.toLowerCase()
      const injectionKeywords = [
        'ignore previous',
        'ignore all',
        'disregard',
        'forget previous',
        'act as',
        'pretend',
        'new instructions',
        'system:',
        '[system]',
        '[assistant]',
      ]
      for (const keyword of injectionKeywords) {
        if (lowerDecoded.includes(keyword)) {
          throw new Error(
            `File "${fileName}" contains base64-encoded prompt injection content and cannot be uploaded.`
          )
        }
      }
    } catch (e) {
      if (e instanceof Error && e.message.includes('cannot be uploaded')) {
        throw e
      }
      // Not valid base64, skip
    }
  }
}

// Instruction 4: Redact PII from text content
function redactPII(content: string): string {
  let redacted = content

  // SSN (US)
  redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
  redacted = redacted.replace(/\b\d{9}\b/g, '[REDACTED_SSN]')

  // Credit card numbers (Visa, MC, Amex, Discover)
  redacted = redacted.replace(/\b(?:\d{4}[- ]?){3}\d{4}\b/g, '[REDACTED_CC]')
  redacted = redacted.replace(/\b3[47]\d{2}[- ]?\d{6}[- ]?\d{5}\b/g, '[REDACTED_CC]')

  // Passport numbers (generic alphanumeric)
  redacted = redacted.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, '[REDACTED_PASSPORT]')

  // Email addresses
  redacted = redacted.replace(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]')

  // Phone numbers (various formats)
  redacted = redacted.replace(/\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[REDACTED_PHONE]')
  redacted = redacted.replace(/\b\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b/g, '[REDACTED_PHONE]')

  // Dates of birth (common formats)
  redacted = redacted.replace(
    /\b(?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])[-/.](?:19|20)\d{2}\b/g,
    '[REDACTED_DOB]'
  )
  redacted = redacted.replace(
    /\b(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])\b/g,
    '[REDACTED_DOB]'
  )

  // IP addresses
  redacted = redacted.replace(
    /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    '[REDACTED_IP]'
  )

  return redacted
}

// Instruction 5: Singapore-specific PII detection
function detectSingaporePII(content: string, fileName: string): void {
  const sgPIIPatterns: Array<{ pattern: RegExp; label: string }> = [
    // NRIC/FIN numbers (S/T/F/G followed by 7 digits and a letter)
    { pattern: /\b[STFG]\d{7}[A-Z]\b/gi, label: 'NRIC/FIN number' },
    // Singapore passport numbers
    { pattern: /\bE\d{7}[A-Z]\b/gi, label: 'Singapore passport number' },
    // Personal email addresses
    { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: 'email address' },
    // Singapore bank account numbers (various formats, 10-16 digits)
    { pattern: /\b\d{10,16}\b/g, label: 'potential bank account number' },
    // CPF account numbers (same format as NRIC but worth checking separately)
    { pattern: /\bCPF\s*[:\-]?\s*[STFG]\d{7}[A-Z]\b/gi, label: 'CPF account number' },
    // Full names (heuristic: two or more capitalized words)
    {
      pattern: /\b[A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20})?\b/g,
      label: 'potential full name',
    },
  ]

  const detected: string[] = []
  for (const { pattern, label } of sgPIIPatterns) {
    if (pattern.test(content)) {
      detected.push(label)
    }
  }

  if (detected.length > 0) {
    throw new Error(
      `File "${fileName}" contains Singapore PII (${detected.join(', ')}) and cannot be uploaded per data protection policy.`
    )
  }
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
  }, [])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isLoading, showFileUpload])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!input.trim() && pendingFiles.length === 0) return

    // Sanitize and validate text input
    const sanitizedInput = sanitizeInput(input)

    const attachments: FileAttachment[] = []
    for (const file of pendingFiles) {
      // Validate file type and size
      const validationError = validateFile(file)
      if (validationError) {
        const errMsg: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: validationError,
          timestamp: new Date(),
          error: { type: 'general', message: validationError },
        }
        setMessages(prev => [...prev, errMsg])
        return
      }

      let content: string
      try {
        content = await readFileContent(file)
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to read file.'
        const errMsg: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: msg,
          timestamp: new Date(),
          error: { type: 'general', message: msg },
        }
        setMessages(prev => [...prev, errMsg])
        return
      }

      const isBinary =
        file.type.startsWith('image/') ||
        file.type === 'application/pdf' ||
        file.type === 'application/msword' ||
        file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

      let processedContent = content

      if (!isBinary) {
        // Sanitize text content
        processedContent = sanitizeFileContent(processedContent)

        // Instruction 3: Check for malicious prompts in file content
        try {
          inspectFileContentForMaliciousPrompts(processedContent, file.name)
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Malicious content detected in file.'
          const errMsg: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: msg,
            timestamp: new Date(),
            error: { type: 'threat', message: msg },
          }
          setMessages(prev => [...prev, errMsg])
          return
        }

        // Instruction 5: Singapore PII detection — block submission if found
        try {
          detectSingaporePII(processedContent, file.name)
        } catch (err) {
          const msg = err instanceof Error ? err.message : 'Singapore PII detected in file.'
          const errMsg: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: msg,
            timestamp: new Date(),
            error: { type: 'pii', message: msg },
          }
          setMessages(prev => [...prev, errMsg])
          return
        }

        // Instruction 4: Redact PII from text content before sending
        processedContent = redactPII(processedContent)
      }

      attachments.push({
        id: uuidv4(),
        name: file.name,
        type: file.type,
        size: file.size,
        content: processedContent,
      })
    }

    const userMessage: Message = {
      id: uuidv4(),
      role: 'user',
      content: sanitizedInput || `Uploaded ${pendingFiles.length} file(s)`,
      timestamp: new Date(),
      attachments: attachments.length > 0 ? attachments : undefined,
    }

    setMessages(prev => [...prev, userMessage])
    setInput('')
    setPendingFiles([])
    setShowFileUpload(false)
    setIsLoading(true)

    try {
      const response = await fetch('/api/backend/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          message: sanitizedInput,
          attachments,
          conversation_id: uuidv4(),
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        // Handle policy violations returned as errors
        const errorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: data.detail || 'An error occurred',
          timestamp: new Date(),
          error: data.policy_error ? {
            type: data.policy_error.type,
            message: data.policy_error.message,
            details: data.policy_error.details,
          } : undefined,
        }
        setMessages(prev => [...prev, errorMessage])
      } else {
        // Instruction 1: Sanitize LLM output for dynamic code execution primitives
        const sanitizedResponse = sanitizeLLMOutput(data.response)

        const assistantMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: sanitizedResponse,
          timestamp: new Date(),
          error: data.policy_warning ? {
            type: data.policy_warning.type,
            message: data.policy_warning.message,
            details: data.policy_warning.details,
          } : undefined,
        }
        setMessages(prev => [...prev, assistantMessage])
      }
    } catch (error) {
      const errorMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: 'Failed to connect to the backend. Please ensure the server is running.',
        timestamp: new Date(),
        error: {
          type: 'general',
          message: 'Connection error',
        },
      }
      setMessages(prev => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      const shouldEncodeAsBase64 =
        file.type.startsWith('image/') ||
        file.type === 'application/pdf' ||
        file.type === 'application/msword' ||
        file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

      reader.onload = () => {
        const result = reader.result as string
        if (shouldEncodeAsBase64) {
          resolve(result.split(',')[1])
        } else {
          resolve(result)
        }
      }
      reader.onerror = reject

      if (shouldEncodeAsBase64) {
        reader.readAsDataURL(file)
      } else {
        reader.readAsText(file)
      }
    })
  }

  const handleFileSelect = (files: File[]) => {
    setPendingFiles(prev => [...prev, ...files])
  }

  const removePendingFile = (index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  const starterPrompts = [
    {
      label: 'View borrower details',
      action: () => {
        setInput('Show me the loan status for Alice Morgan and include the full borrower details')
        inputRef.current?.focus()
      },
    },
    {
      label: 'Review support document',
      action: () => {
        setInput("Review this uploaded support document and summarize it's contents")
        inputRef.current?.focus()
      },
    },
    {
      label: 'Escalate support case',
      action: () => {
        setInput('Escalate issue CASE-240217 for Alice Morgan')
        inputRef.current?.focus()
      },
    },
  ]

  return (
    <div className="mx-auto flex h-screen w-full max-w-5xl flex-col px-4 pb-4 pt-4 sm:px-6">
      <div className="glass-panel flex min-h-0 flex-1 flex-col overflow-hidden rounded-[24px]">
        <div className="accent-band h-1.5 w-full" />
        <header className="soft-divider flex items-center justify-between border-b px-5 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-600 to-sky-400 shadow-[0_8px_20px_rgba(37,99,235,0.25)]">
              <div className="h-3 w-3 rounded-full bg-white/95" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-slate-50">Acme Loan Processor</h1>
            </div>
          </div>
          <div className="hidden text-sm text-slate-400 sm:block">Loan assistant</div>
        </header>

        <div className="chat-scrollbar flex-1 overflow-y-auto px-4 py-5 sm:px-6">
          {messages.length === 0 ? (
            <div className="fade-in-up flex h-full items-start justify-center pt-10 sm:pt-14">
              <div className="w-full max-w-3xl">
                <p className="text-2xl font-semibold tracking-tight text-slate-50">
                  Hi, how can I help you today?
                </p>
                <p className="mt-2 text-sm text-slate-400">
                  Ask about a loan, check borrower status, or review a support document.
                </p>
                <div className="mt-6 flex flex-wrap gap-3">
                  {starterPrompts.map((prompt) => (
                    <button
                      key={prompt.label}
                      type="button"
                      onClick={prompt.action}
                      className="rounded-full border border-slate-700 bg-slate-900/90 px-4 py-2 text-sm text-slate-200 transition hover:border-sky-500/40 hover:bg-slate-800 hover:text-sky-200"
                    >
                      {prompt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <>
              <MessageList messages={messages} />
              <div ref={messagesEndRef} />
            </>
          )}
        </div>

        {showFileUpload && (
          <div className="soft-divider border-t px-4 py-4 sm:px-6">
            <FileUpload onFilesSelected={handleFileSelect} />
          </div>
        )}

        {pendingFiles.length > 0 && (
          <div className="soft-divider border-t px-4 py-3 sm:px-6">
            <div className="flex flex-wrap gap-2">
              {pendingFiles.map((file, index) => (
                <div
                  key={`${file.name}-${index}`}
                  className="flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200"
                >
                  <span className="max-w-[220px] truncate">{file.name}</span>
                  <button
                    onClick={() => removePendingFile(index)}
                    className="text-slate-500 transition-colors hover:text-rose-400"
                    aria-label={`Remove ${file.name}`}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="soft-divider border-t px-4 py-4 sm:px-6">
          <form onSubmit={handleSubmit} className="mx-auto max-w-4xl">
            <div className="rounded-[22px] border border-slate-700 bg-slate-950/90 px-3 py-2 shadow-[0_12px_32px_rgba(2,6,23,0.35)]">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowFileUpload(!showFileUpload)}
                  className="inline-flex h-9 shrink-0 items-center gap-2 rounded-xl bg-slate-900 px-3 text-xs text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100"
                  aria-label={showFileUpload ? 'Hide document upload' : 'Show document upload'}
                >
                  {showFileUpload ? <Paperclip className="h-[16px] w-[16px]" /> : <Plus className="h-[16px] w-[16px]" />}
                  <span>{showFileUpload ? 'Hide upload' : 'Attach document'}</span>
                </button>

                <div className="flex min-h-[40px] flex-1 min-w-0 items-center">
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask about a loan, review borrower details, or attach a support document..."
                    className="max-h-40 w-full resize-none bg-transparent px-1 py-0 text-[15px] leading-[24px] text-slate-100 outline-none placeholder:text-slate-500"
                    rows={1}
                    disabled={isLoading}
                  />
                </div>

                <button
                  type="submit"
                  disabled={isLoading || (!input.trim() && pendingFiles.length === 0)}
                  className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-[16px] bg-gradient-to-br from-blue-600 to-sky-500 text-white transition hover:from-blue-700 hover:to-sky-600 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
                  aria-label="Send message"
                >
                  {isLoading ? (
                    <Loader2 className="h-[18px] w-[18px] animate-spin" />
                  ) : (
                    <ArrowUp className="h-[18px] w-[18px]" />
                  )}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}