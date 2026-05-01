'use client'

import { useState, useCallback } from 'react'
import { Upload, FileText, Image, File } from 'lucide-react'

interface FileUploadProps {
  onFilesSelected: (files: File[]) => void
}

const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB
const MAX_CONTENT_LENGTH = 500000 // 500k characters

const TEXT_BASED_TYPES = [
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'text/html',
  'text/plain',
  'application/json',
]

const TEXT_BASED_EXTENSIONS = ['.pdf', '.doc', '.docx', '.html', '.htm', '.txt', '.json']

function isTextBasedFile(file: File): boolean {
  const hasTextType = TEXT_BASED_TYPES.includes(file.type)
  const hasTextExtension = TEXT_BASED_EXTENSIONS.some(ext =>
    file.name.toLowerCase().endsWith(ext)
  )
  return hasTextType || hasTextExtension
}

function redactPII(content: string): string {
  // Redact email addresses
  let redacted = content.replace(
    /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    '[EMAIL_REDACTED]'
  )
  // Redact phone numbers (various formats)
  redacted = redacted.replace(
    /(\+?\d[\s\-.]?)?(\(?\d{3}\)?[\s\-.]?)(\d{3}[\s\-.]?\d{4})/g,
    '[PHONE_REDACTED]'
  )
  // Redact SSNs
  redacted = redacted.replace(
    /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
    '[SSN_REDACTED]'
  )
  // Redact credit card numbers
  redacted = redacted.replace(
    /\b(?:\d{4}[\s\-]?){3}\d{4}\b/g,
    '[CC_REDACTED]'
  )
  return redacted
}

function containsSingaporePII(content: string): boolean {
  // NRIC/FIN numbers: S/T/F/G followed by 7 digits and a letter
  const nricPattern = /\b[STFG]\d{7}[A-Z]\b/i
  // SingPass identifiers
  const singpassPattern = /singpass/i
  // Singapore phone numbers (+65 followed by 8 digits)
  const sgPhonePattern = /\+65[\s\-]?\d{4}[\s\-]?\d{4}/
  // Singapore postal codes
  const sgPostalPattern = /\bSingapore\s+\d{6}\b/i

  return (
    nricPattern.test(content) ||
    singpassPattern.test(content) ||
    sgPhonePattern.test(content) ||
    sgPostalPattern.test(content)
  )
}

function stripPromptInjectionPatterns(content: string): string {
  // Remove control characters (except common whitespace)
  let cleaned = content.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

  // Strip common prompt injection patterns
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
    /system\s*:\s*/gi,
    /\[INST\]/gi,
    /\[\/INST\]/gi,
    /<\|im_start\|>/gi,
    /<\|im_end\|>/gi,
    /###\s*(instruction|system|human|assistant)/gi,
    /you\s+are\s+now\s+(a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted)/gi,
    /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)/gi,
    /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)/gi,
    /act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted|jailbroken)/gi,
    /do\s+not\s+follow\s+(your\s+)?(previous\s+)?(instructions?|guidelines?|rules?)/gi,
  ]

  for (const pattern of injectionPatterns) {
    cleaned = cleaned.replace(pattern, '')
  }

  return cleaned
}

function scanFileForPromptInjection(content: string, fileName: string): boolean {
  // Check for hidden/invisible text patterns (white-on-white via style attributes)
  const hiddenTextPattern = /style\s*=\s*["'][^"']*(?:color\s*:\s*(?:white|#fff|#ffffff)|font-size\s*:\s*0)[^"']*["']/gi
  if (hiddenTextPattern.test(content)) {
    return false
  }

  // Check for base64-encoded strings
  const base64Pattern = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g
  if (base64Pattern.test(content)) {
    return false
  }

  // Check for leetspeak patterns
  const leetspeakPattern = /(?:[il1|][gq9][n|\/\\][o0][r|][e3]\s*[a@][l1][l1]|[s5][y][s5][t7][e3][m3])/i
  if (leetspeakPattern.test(content)) {
    return false
  }

  // Check for suspicious prompt-injection keywords
  const injectionKeywords = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
    /disregard\s+(all\s+)?(previous|prior|above)/i,
    /forget\s+(all\s+)?(previous|prior|above)/i,
    /you\s+are\s+now\s+/i,
    /act\s+as\s+(if\s+)?(?:a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted|jailbroken)/i,
    /do\s+not\s+follow\s+(your\s+)?(previous\s+)?(instructions?|guidelines?|rules?)/i,
    /override\s+(previous\s+)?(instructions?|directives?|commands?)/i,
    /new\s+instructions?\s*:/i,
    /system\s+prompt\s*:/i,
    /\[system\]/i,
    /\[user\]/i,
    /\[assistant\]/i,
  ]

  for (const pattern of injectionKeywords) {
    if (pattern.test(content)) {
      return false
    }
  }

  // Check for binary/shell command signatures
  const shellCommandPattern = /(?:\/bin\/(?:sh|bash|zsh|fish)|cmd\.exe|powershell|eval\s*\(|exec\s*\(|system\s*\(|subprocess|os\.system)/i
  if (shellCommandPattern.test(content)) {
    return false
  }

  return true
}

async function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = (e) => resolve(e.target?.result as string || '')
    reader.onerror = () => reject(new Error('Failed to read file'))
    reader.readAsText(file)
  })
}

async function sanitizeAndValidateFiles(files: File[]): Promise<File[]> {
  const sanitized: File[] = []

  for (const file of files) {
    // Maximum file size check
    if (file.size > MAX_FILE_SIZE) {
      alert(`File "${file.name}" exceeds the maximum allowed size of 10MB and was skipped.`)
      continue
    }

    if (isTextBasedFile(file)) {
      let content: string
      try {
        content = await readFileAsText(file)
      } catch {
        alert(`File "${file.name}" could not be read and was skipped.`)
        continue
      }

      // Maximum content length check
      if (content.length > MAX_CONTENT_LENGTH) {
        alert(`File "${file.name}" content exceeds the maximum allowed length and was skipped.`)
        continue
      }

      // JSON validation
      if (file.name.toLowerCase().endsWith('.json') || file.type === 'application/json') {
        try {
          JSON.parse(content)
        } catch {
          alert(`File "${file.name}" contains invalid JSON and was skipped.`)
          continue
        }
      }

      // Singapore PII check
      if (containsSingaporePII(content)) {
        alert(`File "${file.name}" contains Singapore PII (e.g., NRIC/FIN, SingPass) and cannot be uploaded.`)
        continue
      }

      // Prompt injection scan
      if (!scanFileForPromptInjection(content, file.name)) {
        alert(`File "${file.name}" contains potentially malicious content and was blocked.`)
        continue
      }

      // Strip prompt injection patterns and control characters
      let sanitizedContent = stripPromptInjectionPatterns(content)

      // Redact PII
      sanitizedContent = redactPII(sanitizedContent)

      // Create a new sanitized File object
      const sanitizedFile = new File([sanitizedContent], file.name, { type: file.type })
      sanitized.push(sanitizedFile)
    } else {
      // Image files pass through unchanged (after size check)
      sanitized.push(file)
    }
  }

  return sanitized
}

export function FileUpload({ onFilesSelected }: FileUploadProps) {
  const [isDragOver, setIsDragOver] = useState(false)

  const handleDrop = useCallback(
    async (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault()
      setIsDragOver(false)

      const files = Array.from(e.dataTransfer.files)
      const validFiles = files.filter(isValidFileType)

      if (validFiles.length > 0) {
        const sanitizedFiles = await sanitizeAndValidateFiles(validFiles)
        if (sanitizedFiles.length > 0) {
          onFilesSelected(sanitizedFiles)
        }
      }
    },
    [onFilesSelected]
  )

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

  const handleFileInput = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files) {
        const files = Array.from(e.target.files)
        const validFiles = files.filter(isValidFileType)

        if (validFiles.length > 0) {
          const sanitizedFiles = await sanitizeAndValidateFiles(validFiles)
          if (sanitizedFiles.length > 0) {
            onFilesSelected(sanitizedFiles)
          }
        }
      }
    },
    [onFilesSelected]
  )

  return (
    <div
      className={`file-upload-zone rounded-[24px] p-6 text-center cursor-pointer ${
        isDragOver ? 'drag-over' : ''
      }`}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
    >
      <input
        type="file"
        multiple
        accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
        className="hidden"
        id="file-upload-input"
        onChange={handleFileInput}
      />
      <label htmlFor="file-upload-input" className="cursor-pointer">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-800 text-slate-200">
          <Upload className="h-6 w-6" />
        </div>
        <p className="mb-2 text-sm font-medium text-slate-100 sm:text-base">
          Drag and drop files here, or click to browse
        </p>
        <p className="mx-auto mb-4 max-w-xl text-sm text-slate-400">
          Add a document to the conversation.
        </p>
        <div className="flex flex-wrap justify-center gap-4 text-xs text-slate-500">
          <div className="flex items-center gap-1">
            <FileText className="h-4 w-4" />
            <span>PDF, DOC, HTML</span>
          </div>
          <div className="flex items-center gap-1">
            <Image className="h-4 w-4" />
            <span>JPG, PNG</span>
          </div>
          <div className="flex items-center gap-1">
            <File className="h-4 w-4" />
            <span>TXT, JSON</span>
          </div>
        </div>
      </label>
    </div>
  )
}

function isValidFileType(file: File): boolean {
  const validTypes = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/html',
    'text/plain',
    'application/json',
    'image/jpeg',
    'image/png',
  ]

  const validExtensions = ['.pdf', '.doc', '.docx', '.html', '.htm', '.txt', '.json', '.jpg', '.jpeg', '.png']

  const hasValidType = validTypes.includes(file.type)
  const hasValidExtension = validExtensions.some(ext =>
    file.name.toLowerCase().endsWith(ext)
  )

  return hasValidType || hasValidExtension
}