"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
"""

import logging
import re
import base64
from typing import Optional

logger = logging.getLogger(__name__)


def _scan_for_malicious_content(text: str, soup=None) -> list:
    """
    Scan content for suspicious patterns including hidden content indicators,
    base64-encoded prompts, leetspeak, AI-injection patterns, and binary/shell commands.
    """
    warnings = []

    # Check for hidden elements in soup
    if soup is not None:
        hidden_selectors = []
        for tag in soup.find_all(True):
            style = tag.get('style', '')
            if style:
                style_lower = style.lower().replace(' ', '')
                if 'display:none' in style_lower:
                    hidden_selectors.append('display:none')
                if 'visibility:hidden' in style_lower:
                    hidden_selectors.append('visibility:hidden')
                # Off-screen positioning
                if re.search(r'(left|top)\s*:\s*-\d{3,}', style_lower):
                    hidden_selectors.append('off-screen positioning')
                # White text on white background
                if 'color:white' in style_lower or 'color:#fff' in style_lower or 'color:#ffffff' in style_lower:
                    hidden_selectors.append('white-on-white text')
                if 'color:rgb(255,255,255)' in style_lower:
                    hidden_selectors.append('white-on-white text (rgb)')
        if hidden_selectors:
            warnings.append(f"Hidden content detected: {', '.join(set(hidden_selectors))}")

    # Check for base64-encoded content that may contain prompts
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    for match in base64_pattern.finditer(text):
        try:
            decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
            if any(kw in decoded.lower() for kw in ['ignore', 'prompt', 'instruction', 'system', 'assistant', 'user', 'jailbreak']):
                warnings.append("Base64-encoded prompt injection detected")
                break
        except Exception:
            pass

    # Check for leetspeak patterns
    leetspeak_pattern = re.compile(r'\b(?:[1!][gq][n][0o][r3][e3]|[1!][gq][n][0o][r3][e3]\s+[a4][l1][l1])\b', re.IGNORECASE)
    if leetspeak_pattern.search(text):
        warnings.append("Leetspeak pattern detected")

    # Check for suspicious AI-injection patterns
    ai_injection_patterns = [
        r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)',
        r'disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)',
        r'forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)',
        r'you\s+are\s+now\s+(a|an)\s+\w+',
        r'act\s+as\s+(a|an)\s+\w+',
        r'pretend\s+(you\s+are|to\s+be)\s+',
        r'new\s+instructions?\s*:',
        r'system\s*:\s*(you|your)',
        r'\[system\]',
        r'\[prompt\]',
        r'\[instruction\]',
        r'<\s*system\s*>',
        r'<\s*prompt\s*>',
        r'jailbreak',
        r'prompt\s+injection',
        r'override\s+(your\s+)?(instructions?|programming|directives?)',
    ]
    for pattern in ai_injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            warnings.append(f"Suspicious AI-injection pattern detected: '{pattern}'")

    # Check for binary/shell commands
    shell_patterns = [
        r'(?:^|\s|;|&&|\|\|)(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen)\s*[\(\s]',
        r'(?:rm\s+-rf|chmod\s+\d+|chown\s+|sudo\s+|wget\s+|curl\s+.*\|\s*(?:bash|sh))',
        r'(?:/bin/|/usr/bin/|/etc/passwd|/etc/shadow)',
        r'(?:0x[0-9a-fA-F]{2}\s*){4,}',
        r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}',
    ]
    for pattern in shell_patterns:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            warnings.append(f"Suspicious binary/shell command pattern detected")
            break

    return warnings


def _remove_hidden_elements(soup) -> None:
    """
    Remove hidden elements from the soup object before text extraction.
    """
    for tag in soup.find_all(True):
        style = tag.get('style', '')
        if style:
            style_lower = style.lower().replace(' ', '')
            if ('display:none' in style_lower or
                    'visibility:hidden' in style_lower or
                    re.search(r'(left|top)\s*:\s*-\d{3,}', style_lower) or
                    'color:white' in style_lower or
                    'color:#fff' in style_lower or
                    'color:#ffffff' in style_lower or
                    'color:rgb(255,255,255)' in style_lower):
                tag.decompose()


class HTMLParser:
    """
    Parses HTML files and extracts text content.
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract visible text from HTML content, removing hidden elements
        and scanning for malicious content.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Scan for hidden content and malicious patterns before removal
            warnings = _scan_for_malicious_content("", soup=soup)

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            # Remove hidden elements before extracting text
            _remove_hidden_elements(soup)

            text = soup.get_text(separator='\n', strip=True)

            # Scan extracted text for additional malicious patterns
            text_warnings = _scan_for_malicious_content(text, soup=None)
            warnings.extend(text_warnings)

            if warnings:
                logger.warning(
                    "Security issues detected during HTML text extraction",
                    extra={"warnings": warnings}
                )

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text),
                }
            )

            return text

        except Exception as e:
            logger.error(f"HTML extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text, removing hidden elements and scanning
        for malicious content.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Scan for hidden content and malicious patterns before removal
            warnings = _scan_for_malicious_content("", soup=soup)

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            # Remove hidden elements before extracting text
            _remove_hidden_elements(soup)

            text = soup.get_text(separator='\n', strip=True)

            # Scan extracted text for additional malicious patterns
            text_warnings = _scan_for_malicious_content(text, soup=None)
            warnings.extend(text_warnings)

            if warnings:
                logger.warning(
                    "Security issues detected during HTML visible-only extraction",
                    extra={"warnings": warnings}
                )

            logger.info(
                "HTML visible-only text extraction complete",
                extra={
                    "text_length": len(text),
                }
            )

            return text

        except Exception as e:
            logger.error(f"HTML visible-only extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags).
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                metadata['title'] = title.get_text()

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    metadata[name] = content

            return metadata

        except Exception as e:
            logger.error(f"HTML metadata extraction error: {e}")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML with security scanning.
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')

        # Scan for hidden content and malicious patterns before removal
        warnings = _scan_for_malicious_content("", soup=soup)

        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        # Scan extracted text for additional malicious patterns
        text_warnings = _scan_for_malicious_content(text, soup=None)
        # Deduplicate warnings
        for w in text_warnings:
            if w not in warnings:
                warnings.append(w)

        if warnings:
            logger.warning(
                "Security issues detected during HTML extract_all",
                extra={"warnings": warnings}
            )

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }