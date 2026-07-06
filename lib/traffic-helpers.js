function getNidsFieldValue(field, item) {
  const map = {
    'ip.src': 'srcIp', 'ip.dst': 'destIp',
    'tcp.srcport': 'srcPort', 'tcp.dstport': 'destPort',
    'udp.srcport': 'srcPort', 'udp.dstport': 'destPort',
    'frame.len': 'bytes', 'frame.protocols': 'protocol', 'ip.proto': 'protocol',
    'http.method': 'httpMethod', 'http.request.method': 'httpMethod',
    'http.uri': 'httpUri', 'http.request.uri': 'httpUri',
    'http.status': 'httpStatus', 'http.response.code': 'httpStatus',
    'http.host': 'httpHost', 'http.user_agent': 'httpUserAgent',
    'http.content_type': 'httpContentType'
  };
  if (field === 'ip.addr') return `${item.srcIp} ${item.destIp}`;
  if (field === 'tcp.port') return `${item.srcPort} ${item.destPort}`;
  const mapped = map[field];
  if (mapped && item[mapped] !== undefined) return item[mapped];
  if (item[field] !== undefined) return item[field];
  return null;
}

function evaluateSingleExpr(token, item) {
  const match = token.match(/^([\w.]+)\s*([!=<>]+|contains|matches)\s*(.+)$/i);
  if (!match) {
    if (token.startsWith('!')) return !evaluateSingleExpr(token.slice(1), item);
    return false;
  }
  const [, field, operator, valueRaw] = match;
  const value = valueRaw.replace(/^"|"$/g, '').toLowerCase();
  const fieldValue = getNidsFieldValue(field, item);
  if (fieldValue === null || fieldValue === undefined) return false;
  const strVal = String(fieldValue).toLowerCase();
  switch (operator) {
    case '==': return strVal === value;
    case '!=': return strVal !== value;
    case '>': return parseFloat(strVal) > parseFloat(value);
    case '<': return parseFloat(strVal) < parseFloat(value);
    case '>=': return parseFloat(strVal) >= parseFloat(value);
    case '<=': return parseFloat(strVal) <= parseFloat(value);
    case 'contains': return strVal.includes(value);
    case 'matches':
      try { const re = new RegExp(value, 'i'); return re.test(strVal); } catch { return false; }
    default: return true;
  }
}

function evaluateTokens(tokens, item) {
  let result = true; let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    if (token === '(') {
      const subTokens = []; let depth = 1; i++;
      while (i < tokens.length && depth > 0) {
        if (tokens[i] === '(') depth++;
        else if (tokens[i] === ')') { depth--; if (depth === 0) break; }
        subTokens.push(tokens[i]); i++;
      }
      const subResult = evaluateTokens(subTokens, item);
      if (i < tokens.length - 1 && (tokens[i + 1] === '&&' || tokens[i + 1] === 'and')) { result = result && subResult; i += 2; }
      else if (i < tokens.length - 1 && (tokens[i + 1] === '||' || tokens[i + 1] === 'or')) { result = result || subResult; i += 2; }
      else result = result && subResult;
    } else if (token === '!' || token === 'not') {
      i++; result = result && !evaluateTokens([tokens[i]], item); i++;
    } else if (token === '&&' || token === 'and' || token === '||' || token === 'or') { i++; }
    else {
      const exprResult = evaluateSingleExpr(token, item);
      if (i < tokens.length - 1 && (tokens[i + 1] === '&&' || tokens[i + 1] === 'and')) { result = result && exprResult; i += 2; }
      else if (i < tokens.length - 1 && (tokens[i + 1] === '||' || tokens[i + 1] === 'or')) { result = result || exprResult; i += 2; }
      else { result = result && exprResult; i++; }
    }
  }
  return result;
}

function isWebFlow(f) { return f.httpMethod || (f.protocol && (f.protocol === 'HTTP' || f.protocol === 'HTTPS')); }

module.exports = { evaluateTokens, evaluateSingleExpr, getNidsFieldValue, isWebFlow };
