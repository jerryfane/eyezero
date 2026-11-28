// Zero-dependency lexer-based JS, CSS, and HTML minifier for Bitcoin inscription builds.
// Preserves ASI newlines and never mutates strings, template literals, or regex literals.

const REGEX_PREV_KEYWORDS = new Set([
  'return', 'throw', 'case', 'in', 'of', 'typeof', 'void', 'delete', 'new', 'yield', 'await', 'else', 'do',
]);
const REGEX_PREV_PUNCT = new Set(['(', '[', '{', ',', ';', ':', '=', '!', '?', '&', '|', '^', '~', '+', '-', '*', '%', '<', '>']);

function lastNonWsTokenKind(out) {
  let j = out.length - 1;
  while (j >= 0 && (out[j] === ' ' || out[j] === '\t' || out[j] === '\n' || out[j] === '\r')) j--;
  if (j < 0) return 'start';
  const ch = out[j];
  // Postfix ++ / -- followed by / is division (e.g. a++ / 2), not a regex literal.
  if ((ch === '+' || ch === '-') && j > 0 && out[j - 1] === ch) return 'other';
  if (REGEX_PREV_PUNCT.has(ch)) return 'punct';
  if (/[A-Za-z0-9_$]/.test(ch)) {
    let k = j;
    while (k >= 0 && /[A-Za-z0-9_$]/.test(out[k])) k--;
    const word = out.slice(k + 1, j + 1);
    return REGEX_PREV_KEYWORDS.has(word) ? 'kw' : 'ident';
  }
  return 'other';
}

export function minifyJs(src) {
  const n = src.length;
  let i = 0;
  let out = '';

  const copyString = (quote) => {
    out += src[i++];
    while (i < n) {
      const c = src[i++];
      out += c;
      if (c === '\\' && i < n) {
        out += src[i++];
      } else if (c === quote) {
        break;
      }
    }
  };

  const copyTemplate = () => {
    out += src[i++]; // opening `
    while (i < n) {
      const c = src[i++];
      out += c;
      if (c === '\\' && i < n) {
        out += src[i++];
      } else if (c === '`') {
        break;
      } else if (c === '$' && src[i] === '{') {
        out += src[i++]; // {
        let depth = 1;
        while (i < n && depth > 0) {
          const ch = src[i];
          if (ch === "'" || ch === '"') {
            copyString(ch);
          } else if (ch === '`') {
            copyTemplate();
          } else if (ch === '/' && src[i + 1] === '/') {
            i += 2;
            while (i < n && src[i] !== '\n') i++;
          } else if (ch === '/' && src[i + 1] === '*') {
            i += 2;
            let hasNl = false;
            while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
              if (src[i] === '\n' || src[i] === '\r' || src[i] === '\u2028' || src[i] === '\u2029') hasNl = true;
              i++;
            }
            i += 2;
            if (hasNl) out += '\n';
            else if (out.length && !/[ \t\n]/.test(out[out.length - 1])) out += ' ';
          } else if (ch === '/' && ['start', 'punct', 'kw'].includes(lastNonWsTokenKind(out))) {
            copyRegex();
          } else {
            if (ch === '{') depth++;
            else if (ch === '}') depth--;
            out += src[i++];
          }
        }
      }
    }
  };

  const copyRegex = () => {
    out += src[i++]; // opening /
    let inClass = false;
    while (i < n) {
      const c = src[i++];
      out += c;
      if (c === '\\' && i < n) {
        out += src[i++];
      } else if (c === '[') {
        inClass = true;
      } else if (c === ']') {
        inClass = false;
      } else if (c === '/' && !inClass) {
        while (i < n && /[a-z]/i.test(src[i])) out += src[i++];
        break;
      }
    }
  };

  while (i < n) {
    const ch = src[i];
    if (ch === "'" || ch === '"') {
      copyString(ch);
      continue;
    }
    if (ch === '`') {
      copyTemplate();
      continue;
    }
    if (ch === '/' && src[i + 1] === '/') {
      i += 2;
      while (i < n && src[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && src[i + 1] === '*') {
      i += 2;
      let hasNl = false;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n' || src[i] === '\r' || src[i] === '\u2028' || src[i] === '\u2029') hasNl = true;
        i++;
      }
      i += 2;
      if (hasNl) {
        while (out.length && (out[out.length - 1] === ' ' || out[out.length - 1] === '\t')) out = out.slice(0, -1);
        if (out.length && out[out.length - 1] !== '\n') out += '\n';
      } else if (out.length && !/[ \t\n]/.test(out[out.length - 1])) {
        out += ' ';
      }
      continue;
    }
    if (ch === '/') {
      const prev = lastNonWsTokenKind(out);
      if (prev === 'start' || prev === 'punct' || prev === 'kw') {
        copyRegex();
        continue;
      }
    }
    if (ch === '\r') {
      i++;
      continue;
    }
    if (ch === '\n') {
      i++;
      // Strip trailing spaces on current line and collapse blank lines; preserve single newline for ASI safety.
      while (out.length && (out[out.length - 1] === ' ' || out[out.length - 1] === '\t')) {
        out = out.slice(0, -1);
      }
      if (out.length && out[out.length - 1] !== '\n') out += '\n';
      while (i < n && (src[i] === ' ' || src[i] === '\t' || src[i] === '\r' || src[i] === '\n')) i++;
      continue;
    }
    if (ch === ' ' || ch === '\t') {
      while (i < n && (src[i] === ' ' || src[i] === '\t')) i++;
      if (out.length && out[out.length - 1] !== '\n' && out[out.length - 1] !== ' ') {
        out += ' ';
      }
      continue;
    }
    out += src[i++];
  }

  return out.trim() + '\n';
}

export function minifyCss(css) {
  let out = '';
  const n = css.length;
  let i = 0;
  // Never strip whitespace BEFORE ':' so descendant pseudo-selectors like `.toolbar :focus` stay intact.
  const PUNCT = new Set(['{', ';', ',', '>', '~', '}']);
  while (i < n) {
    const ch = css[i];
    if (ch === '"' || ch === "'") {
      const q = ch;
      out += css[i++];
      while (i < n) {
        const c = css[i++];
        out += c;
        if (c === '\\' && i < n) out += css[i++];
        else if (c === q) break;
      }
      continue;
    }
    if (ch === '/' && css[i + 1] === '*') {
      i += 2;
      while (i < n && !(css[i] === '*' && css[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (/\s/.test(ch)) {
      while (i < n && /\s/.test(css[i])) i++;
      const prev = out[out.length - 1];
      const next = css[i];
      if (out.length && prev !== ' ' && prev !== ':' && !PUNCT.has(prev) && next && !PUNCT.has(next)) {
        out += ' ';
      }
      continue;
    }
    if (ch === ':') {
      out += css[i++];
      while (i < n && /\s/.test(css[i])) i++;
      continue;
    }
    if (PUNCT.has(ch)) {
      while (out.length && out[out.length - 1] === ' ') out = out.slice(0, -1);
      if (ch === '}' && out.endsWith(';')) out = out.slice(0, -1);
      out += css[i++];
      while (i < n && /\s/.test(css[i])) i++;
      continue;
    }
    out += css[i++];
  }
  return out.trim();
}

const BLOCK_TAGS = 'html|head|body|meta|title|link|style|script|header|nav|aside|main|section|div|table|thead|tbody|tr|th|td|ul|ol|li|pre|hr|br';
const BEFORE_BLOCK_RE = new RegExp(`>\\s+(?=<\\/?(?:${BLOCK_TAGS})\\b)`, 'gi');
const AFTER_BLOCK_RE = new RegExp(`(<\\/?(?:${BLOCK_TAGS})\\b[^>]*>)\\s+<`, 'gi');

export function minifyHtml(html) {
  // 1. Protect <style> and <script> blocks while minifying each with its proper minifier.
  const blocks = [];
  let work = html.replace(/<style([^>]*)>([\s\S]*?)<\/style>/gi, (_, attrs, body) => {
    const idx = blocks.length;
    blocks.push(`<style${attrs}>${minifyCss(body)}</style>`);
    return `__EYEZERO_BLK_${idx}__`;
  });
  work = work.replace(/<script([^>]*)>([\s\S]*?)<\/script>/gi, (_, attrs, body) => {
    const idx = blocks.length;
    const isJson = /application\/json/i.test(attrs);
    const minBody = isJson ? JSON.stringify(JSON.parse(body)) : minifyJs(body);
    blocks.push(`<script${attrs}>${minBody}</script>`);
    return `__EYEZERO_BLK_${idx}__`;
  });

  // 2. Strip HTML comments and collapse structural whitespace without removing separators between inline elements.
  work = work
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/\r?\n\s*/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .replace(BEFORE_BLOCK_RE, '>')
    .replace(AFTER_BLOCK_RE, '$1<')
    .trim();

  // 3. Restore protected blocks.
  for (let i = 0; i < blocks.length; i++) {
    work = work.replace(`__EYEZERO_BLK_${i}__`, () => blocks[i]);
  }
  return work + '\n';
}
