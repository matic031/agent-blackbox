/**
 * Record → RDF mapping. THIS IS THE FILE YOU ADAPT for your own dataset.
 *
 * Two exports:
 *   recordKey(record)   -> stable string key; drives the entity URI and dedup.
 *                          Two records with the same key are THE SAME entity —
 *                          the DKG rejects re-minting an existing rootEntity
 *                          in a context graph (validation "Rule 4").
 *   recordQuads(record) -> array of {subject, predicate, object, graph:''}
 *                          quads for one record.
 *
 * RDF term rules (V10 node API):
 *   - subject/predicate: bare absolute IRIs (no <>)
 *   - object: bare absolute IRI, OR an N-Triples-quoted literal ("...")
 *   - NO blank nodes (rejected by the node) — skolemize lists if you need them
 *   - keep literals well under ~100 KB (oversize literals are tombstoned)
 *   - publish timestamps as PLAIN string literals; typed ^^xsd:dateTime hits a
 *     publisher↔peer canonicalization skew on Base mainnet (mint fails)
 *
 * The example below maps AI/security threat signals (dependency advisories,
 * IOCs, prompt-injection patterns). Replace with your own schema.
 */
import { createHash } from 'node:crypto';

const NS = 'urn:defender:';              // change to your project namespace
const P = `${NS}p:`;
const SCHEMA = 'http://schema.org/';
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type';

const esc = (s) => String(s)
  .replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  .replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t');
const lit = (s) => `"${esc(s)}"`;
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 24);

const dependencyName = (s) => {
  const name = String(s.package ?? s.name ?? s.package_name ?? '').trim();
  return name.startsWith('@') ? `@${name.replace(/^@+/, '')}` : name;
};
const dependencyVersion = (s) => String(s.version ?? s.package_version ?? '').trim();
const canonicalPackageName = (ecosystem, name) => {
  const normalized = String(name).trim().toLowerCase();
  return String(ecosystem).trim().toLowerCase() === 'pypi'
    ? normalized.replace(/[-_.]+/g, '-')
    : normalized;
};
const canonicalIoc = (s) => {
  let type = String(s.ioc_type ?? s.iocType ?? '').trim().toLowerCase();
  let value = String(s.value ?? s.indicator ?? '').trim();
  if (type === 'ipv4' || type === 'ipv6') type = 'ip';
  if (['sha256', 'sha1', 'sha512', 'md5'].includes(type)) {
    if (!/^(?:sha256|sha1|sha512|md5):/i.test(value)) value = `${type}:${value}`;
    type = 'hash';
  }
  if (type === 'domain') value = value.replace(/\.$/, '').toLowerCase();
  else if (type === 'url') {
    const match = value.match(/^([^:]+):\/\/([^/]+)(.*)$/);
    if (match) value = `${match[1].toLowerCase()}://${match[2].toLowerCase()}${match[3]}`;
    value = value.replace(/\/+$/, '');
  } else if (type === 'ip') value = value.split(':', 1)[0];
  else if (type === 'hash') value = value.toLowerCase();
  else if ((type === 'wallet' || type === 'contract') && /^0x[a-f0-9]{40}$/i.test(value)) value = value.toLowerCase();
  return { type, value };
};

export function recordKey(s) {
  switch (s.type) {
    case 'dependency': {
      const ecosystem = String(s.ecosystem ?? '').trim().toLowerCase();
      return `dep:${ecosystem}:${canonicalPackageName(ecosystem, dependencyName(s))}@${dependencyVersion(s)}`;
    }
    case 'ioc': {
      const ioc = canonicalIoc(s);
      return `ioc:${ioc.type}:${ioc.value}`;
    }
    case 'injection': return `injection:${sha(String(s.pattern ?? '').trim())}`;
    case 'skill': {
      const name = String(s.skillName ?? s.skill_name ?? s.name ?? '').trim().toLowerCase();
      const version = String(s.skillVersion ?? s.skill_version ?? s.version ?? '').trim();
      const shape = String(s.dangerShape ?? s.danger_shape ?? '').trim();
      return version ? `skill:${name}@${version}` : `skill:${name}:${shape}`;
    }
    default: return `rec:${JSON.stringify(s)}`;
  }
}

const TYPE_IRI = {
  dependency: `${NS}DependencySignal`,
  ioc: `${NS}IocSignal`,
  injection: `${NS}InjectionSignal`,
  skill: `${NS}SkillSignal`,
};

export function recordQuads(s) {
  const subj = `${NS}signal:${sha(recordKey(s))}`;
  const q = [];
  const add = (p, o) => { if (o !== undefined && o !== null && o !== '') q.push({ subject: subj, predicate: p, object: o, graph: '' }); };
  const addLit = (p, v) => { if (v !== undefined && v !== null && v !== '') add(p, lit(v)); };

  add(RDF_TYPE, TYPE_IRI[s.type] ?? `${NS}Signal`);
  addLit(SCHEMA + 'name', s.title);
  addLit(SCHEMA + 'description', s.description ?? s.summary);
  addLit(P + 'severity', s.severity);
  addLit(P + 'source', s.source);
  addLit(P + 'contributor', s.contributor);
  addLit(P + 'family', s.family);
  for (const t of s.tags ?? []) addLit(P + 'tag', t);
  for (const r of s.references ?? []) addLit(SCHEMA + 'citation', r);

  if (s.type === 'dependency') {
    addLit(P + 'ecosystem', s.ecosystem);
    addLit(P + 'package', dependencyName(s));
    addLit(P + 'version', dependencyVersion(s));
    addLit(P + 'kind', s.kind);
    addLit(P + 'advisoryId', s.advisoryId);
  } else if (s.type === 'ioc') {
    const ioc = canonicalIoc(s);
    addLit(P + 'iocType', ioc.type);
    addLit(P + 'value', ioc.value);
    addLit(P + 'threat', s.threat);
    addLit(P + 'malware', s.malware);
    if (s.confidence !== undefined) addLit(P + 'confidence', String(s.confidence));
    addLit(P + 'firstSeen', s.first_seen); // plain string on purpose — see header
  } else if (s.type === 'injection' || s.type === 'skill') {
    addLit(P + 'pattern', s.pattern);
    addLit(P + 'owasp', s.owasp);
  }
  return q;
}

/**
 * Extract the flat record list from your source file. The example understands
 * the Blackbox seed-bundle shape ({dependencies, injection, skills, iocs});
 * replace with whatever your source looks like (or just `return json` for a
 * plain array).
 */
export function extractRecords(json) {
  if (Array.isArray(json)) return json;
  return [
    ...(json.injection ?? []),
    ...(json.skills ?? []),
    ...(json.dependencies ?? []),
    ...(json.iocs ?? []),
  ];
}
