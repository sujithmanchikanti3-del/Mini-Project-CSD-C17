import { isRoleBearingCategory, matchDependencyRule, normalizePackageName } from '../architecture/architectureRules';
import { ArchitectureComponent, ArchitectureEvidence, ComponentTechnology } from '../architecture/types';
import { Ecosystem } from '../scanner/technology/types';
import {
  RuleContext,
  RuleFinding,
  StrideCategory,
  StrideRule,
  ThreatObservation,
  ThreatTarget,
} from './types';

/* =============================================================================================
 * Global limitations: true for every project, because of what the V0.4 model does not contain.
 * ========================================================================================== */

export const GLOBAL_LIMITATIONS: readonly string[] = [
  'The architecture model establishes no data flows and no trust boundaries; none are assumed or inferred.',
  'Authentication, authorization, TLS and secrets configuration are not read, so their presence or absence is not known.',
  'Compose ports, container user, privileged mode, volumes and environment, and Dockerfile USER, are not extracted by the earlier milestones and are not assessed.',
  'Source code is not analysed; controls implemented in code, middleware or infrastructure are not visible.',
  'A declared library is not evidence that it is used, or used correctly; a missing library is not evidence that a control is missing.',
  'Lockfiles are not read, so resolved dependency versions are not known.',
  'Frontend-specific threats (for example client-side injection) need source analysis and are not assessed.',
  'Results are candidates for review. They are not confirmed vulnerabilities and are not prioritised or scored.',
];

/* =============================================================================================
 * Curated recognised-control libraries. Matching is on NORMALISED package names (see
 * normalizePackageName: lower-case; Python also folds "_" and "." to "-"). A finite list can
 * never be complete, and every threat that depends on it says so.
 * ========================================================================================== */

export type ControlKind = 'authentication' | 'authorization' | 'logging' | 'rate-limiting';

interface ControlEntry {
  exact?: readonly string[];
  prefix?: readonly string[];
}

const SPRING_SECURITY: ControlEntry = {
  prefix: ['org.springframework.boot:spring-boot-starter-security', 'org.springframework.security:'],
};

export const CONTROL_LIBRARIES: Readonly<Record<ControlKind, Partial<Record<Ecosystem, ControlEntry>>>> = {
  authentication: {
    'Node.js': {
      exact: [
        'passport', 'jsonwebtoken', 'jose', 'express-session', 'cookie-session', 'next-auth', 'express-jwt', 'koa-passport',
        'koa-jwt', 'openid-client', 'express-openid-connect', 'keycloak-connect', 'oidc-provider', '@nestjs/passport',
        '@nestjs/jwt', '@fastify/jwt', '@fastify/auth', '@fastify/passport', '@fastify/session', '@hapi/jwt', '@hapi/basic',
      ],
      prefix: ['passport-', '@auth0/', '@clerk/', '@okta/', '@auth/'],
    },
    Python: {
      exact: [
        'flask-login', 'flask-jwt-extended', 'flask-security', 'flask-security-too', 'flask-httpauth', 'flask-oidc', 'authlib',
        'django-allauth', 'django-oauth-toolkit', 'djangorestframework-simplejwt', 'social-auth-app-django', 'fastapi-users',
        'fastapi-jwt-auth', 'python-jose', 'pyjwt', 'oauthlib',
      ],
    },
    Java: {
      prefix: [
        ...SPRING_SECURITY.prefix!, 'org.pac4j:', 'io.jsonwebtoken:', 'org.keycloak:', 'org.apache.shiro:', 'io.micronaut.security:',
        'io.quarkus:quarkus-security', 'io.quarkus:quarkus-oidc',
      ],
      exact: ['com.auth0:java-jwt'],
    },
    Go: {
      prefix: [
        'github.com/golang-jwt/jwt', 'github.com/dgrijalva/jwt-go', 'github.com/coreos/go-oidc', 'github.com/markbates/goth',
        'github.com/gorilla/sessions', 'golang.org/x/oauth2',
      ],
    },
    Rust: {
      exact: [
        'jsonwebtoken', 'oauth2', 'openidconnect', 'actix-identity', 'actix-session', 'actix-web-httpauth', 'axum-login',
        'tower-sessions',
      ],
    },
  },
  authorization: {
    'Node.js': {
      exact: ['casbin', 'node-casbin', '@casl/ability', '@nestjs/casl', 'accesscontrol', 'role-acl', 'express-jwt-authz', 'keycloak-connect', 'oso'],
    },
    Python: {
      exact: [
        'django-guardian', 'django-rules', 'rules', 'casbin', 'pycasbin', 'flask-principal', 'flask-security', 'flask-security-too',
        'oso', 'fastapi-permissions', 'django-role-permissions',
      ],
    },
    Java: { prefix: [...SPRING_SECURITY.prefix!, 'org.apache.shiro:', 'org.casbin:', 'org.keycloak:'] },
    Go: { prefix: ['github.com/casbin/casbin', 'github.com/open-policy-agent/opa', 'github.com/mikespook/gorbac'] },
    Rust: { exact: ['casbin', 'oso'], prefix: ['actix-casbin'] },
  },
  logging: {
    // Only ecosystems without a standard-library logging facility are assessed; see the R-001 rule.
    'Node.js': { exact: ['winston', 'pino', 'pino-http', 'bunyan', 'log4js', 'morgan', 'express-winston', 'roarr', 'tslog'] },
    Rust: { exact: ['log', 'tracing', 'tracing-subscriber', 'env_logger', 'slog', 'fern', 'simplelog', 'flexi_logger'] },
  },
  'rate-limiting': {
    'Node.js': {
      exact: [
        'express-rate-limit', 'rate-limiter-flexible', '@fastify/rate-limit', 'koa-ratelimit', 'koa2-ratelimit',
        '@nestjs/throttler', 'express-slow-down', 'hapi-rate-limit', 'limiter',
      ],
    },
    Python: { exact: ['flask-limiter', 'slowapi', 'django-ratelimit', 'fastapi-limiter', 'limits', 'ratelimit'] },
    Java: {
      prefix: ['com.bucket4j:', 'com.giffing.bucket4j.spring.boot.starter:', 'io.github.resilience4j:'],
      exact: ['com.github.vladimir-bukhtoyarov:bucket4j'],
    },
    Go: { prefix: ['github.com/ulule/limiter', 'golang.org/x/time', 'github.com/didip/tollbooth', 'github.com/juju/ratelimit'] },
    Rust: { exact: ['governor', 'tower_governor', 'tower-governor', 'actix-governor', 'axum-governor', 'actix-limitation'] },
  },
};

/** Does `name` (declared in `ecosystem`) match a recognised library for the control? */
export function matchesControl(kind: ControlKind, ecosystem: Ecosystem, name: string): boolean {
  const entry = CONTROL_LIBRARIES[kind][ecosystem];
  if (!entry) {
    return false;
  }
  const normalized = normalizePackageName(ecosystem, name);
  return (entry.exact?.includes(normalized) ?? false) || (entry.prefix?.some((p) => normalized.startsWith(p)) ?? false);
}

/**
 * Backend frameworks (V0.4 rule labels) that ship their own authentication/authorization facilities.
 * For these, "no authentication library declared" is meaningless, so the rules report "not assessed".
 */
export const FRAMEWORKS_WITH_BUILT_IN_ACCESS_CONTROL: ReadonlySet<string> = new Set(['Django', 'Hapi']);

/** Ecosystems whose standard library provides logging: absence of a logging library says nothing there. */
const ECOSYSTEMS_WITHOUT_STDLIB_LOGGING: readonly Ecosystem[] = ['Node.js', 'Rust'];

/* =============================================================================================
 * Small helpers
 * ========================================================================================== */

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

function cloneEvidence(list: readonly ArchitectureEvidence[]): ArchitectureEvidence[] {
  return list.map((e) => ({ ...e, ...(e.detail ? { detail: { ...e.detail } } : {}) }));
}

function componentTarget(c: ArchitectureComponent): ThreatTarget {
  return { kind: 'component', id: c.id, name: c.name };
}

function displayVersion(version: string | null): string {
  return version === null ? '(no version declared)' : version === '' ? '(empty)' : version;
}

function unique<T>(items: readonly T[]): T[] {
  return [...new Set(items)];
}

function sortedTechnologies(c: ArchitectureComponent): ComponentTechnology[] {
  return [...c.technologies].sort(
    (a, b) => compare(a.ecosystem, b.ecosystem) || compare(a.name, b.name) || compare(a.version ?? '', b.version ?? '')
  );
}

/** Evidence of the one declaration (file + category + version) a technology entry came from; falls back to all evidence. */
function declarationEvidence(lib: ArchitectureComponent, tech: ComponentTechnology): ArchitectureEvidence[] {
  const exact = lib.evidence.filter(
    (e) => e.source === tech.source && e.detail?.category === tech.category && e.detail?.version === tech.version
  );
  return cloneEvidence(exact.length > 0 ? exact : lib.evidence);
}

/** Evidence showing which manifests of a module were inspected (the basis of "not declared" observations). */
function inspectedManifestEvidence(module: ArchitectureComponent): ArchitectureEvidence[] {
  const manifests = module.evidence.filter((e) => e.kind === 'manifest-file');
  return cloneEvidence(manifests.length > 0 ? manifests : module.evidence);
}

function dependencyLabel(tech: ComponentTechnology): string {
  return `${tech.name} ${displayVersion(tech.version)}`;
}

/* =============================================================================================
 * Control-absence rules for Backend components (S-001, R-001, D-001, E-001)
 * ========================================================================================== */

interface ControlRuleConfig {
  id: string;
  category: StrideCategory;
  summary: string;
  kind: ControlKind;
  /** Short noun used in statements, e.g. "authentication". */
  label: string;
  title: (backendName: string) => string;
  description: string;
  assumptions: readonly string[];
  /** Ecosystems for which the absence of a recognised library is meaningful; others are "not assessed". */
  assessedEcosystems?: readonly Ecosystem[];
  notAssessedEcosystemReason?: (ecosystem: Ecosystem) => string;
  /** Frameworks with built-in facilities for this control; "not assessed" for them. */
  builtInFrameworks?: ReadonlySet<string>;
}

interface BackendFramework {
  ecosystem: Ecosystem;
  label: string;
  tech: ComponentTechnology;
}

/** The frameworks that identified the Backend, using the same V0.4 rule table that created the component. */
function backendFrameworks(backend: ArchitectureComponent): BackendFramework[] {
  const found: BackendFramework[] = [];
  for (const tech of sortedTechnologies(backend)) {
    if (tech.kind !== 'dependency') continue;
    const rule = matchDependencyRule({ name: tech.name, ecosystem: tech.ecosystem, category: tech.category ?? 'dependencies' });
    if (rule && rule.role === 'backend') {
      found.push({ ecosystem: tech.ecosystem, label: rule.label, tech });
    }
  }
  return found;
}

function controlAbsenceRule(config: ControlRuleConfig): StrideRule {
  return {
    id: config.id,
    category: config.category,
    basis: 'assumption-dependent',
    summary: config.summary,
    evaluate(ctx: RuleContext): RuleFinding[] {
      const findings: RuleFinding[] = [];
      const notAssessed = (backend: ArchitectureComponent, reason: string): void => {
        findings.push({ kind: 'not-assessed', targetId: backend.id, targetName: backend.name, reason });
      };

      for (const backend of ctx.componentsOfType('Backend')) {
        const module = ctx.moduleOf(backend.id);
        if (!module) {
          notAssessed(backend, 'The model establishes no containing module for this Backend, so its declared libraries cannot be inspected.');
          continue;
        }
        const frameworks = backendFrameworks(backend);
        const ecosystems = unique(frameworks.map((f) => f.ecosystem)).sort();
        if (ecosystems.length === 0) {
          notAssessed(backend, 'The model records no identifying framework dependency for this Backend, so its ecosystem is unknown.');
          continue;
        }

        // Runtime-category libraries declared by the module (dev/test/peer dependencies are not active controls).
        const declared = ctx.declaredLibraries(module.id).flatMap((lib) => sortedTechnologies(lib).map((tech) => ({ lib, tech })));
        const runtime = declared.filter((d) => isRoleBearingCategory(d.tech.category ?? 'dependencies'));

        const absent: Ecosystem[] = [];
        const present: Array<{ lib: ArchitectureComponent; tech: ComponentTechnology }> = [];
        for (const ecosystem of ecosystems) {
          if (config.assessedEcosystems && !config.assessedEcosystems.includes(ecosystem)) {
            notAssessed(backend, config.notAssessedEcosystemReason?.(ecosystem) ?? `${ecosystem} is not assessed for this rule.`);
            continue;
          }
          const labels = frameworks.filter((f) => f.ecosystem === ecosystem).map((f) => f.label);
          if (config.builtInFrameworks && labels.every((l) => config.builtInFrameworks!.has(l))) {
            notAssessed(
              backend,
              `${unique(labels).join(', ')} includes built-in ${config.label} facilities, so the absence of a separate library is not meaningful; whether they are used is not observable.`
            );
            continue;
          }
          const matches = runtime.filter((d) => d.tech.ecosystem === ecosystem && matchesControl(config.kind, ecosystem, d.tech.name));
          if (matches.length > 0) present.push(...matches);
          else absent.push(ecosystem);
        }
        if (absent.length === 0) {
          continue; // a recognised control library is declared: nothing to report for this rule
        }

        const observations: ThreatObservation[] = [
          {
            statement: `${backend.name} is inferred from declared framework dependencies (${frameworks.map((f) => dependencyLabel(f.tech)).join(', ')}).`,
            evidence: cloneEvidence(backend.evidence),
          },
          {
            statement:
              `No recognised ${config.label} library is declared among the ${runtime.filter((d) => absent.includes(d.tech.ecosystem)).length} runtime dependencies ` +
              `of module "${module.name}" (${absent.join(', ')}).`,
            evidence: inspectedManifestEvidence(module),
          },
        ];
        for (const d of present) {
          observations.push({
            statement: `A recognised ${config.label} library is declared for ${d.tech.ecosystem}: ${dependencyLabel(d.tech)}.`,
            evidence: declarationEvidence(d.lib, d.tech),
          });
        }
        for (const d of declared) {
          if (
            absent.includes(d.tech.ecosystem) &&
            !isRoleBearingCategory(d.tech.category ?? 'dependencies') &&
            matchesControl(config.kind, d.tech.ecosystem, d.tech.name)
          ) {
            observations.push({
              statement: `${dependencyLabel(d.tech)} is a recognised ${config.label} library but is declared only in the non-runtime category "${d.tech.category}" and is not counted.`,
              evidence: declarationEvidence(d.lib, d.tech),
            });
          }
        }

        findings.push({
          kind: 'threat',
          target: componentTarget(backend),
          title: config.title(backend.name),
          description: config.description,
          relatedComponentIds: [module.id],
          observations,
          assumptions: [...config.assumptions],
          limitations: unique([
            ...backend.uncertainty,
            `Only libraries declared in the manifests of module "${module.name}" are inspected; ${config.label} implemented in other modules, in source code, or in infrastructure is not visible.`,
            `The list of recognised ${config.label} libraries is finite and curated; an unlisted library would not be recognised.`,
          ]),
        });
      }
      return findings;
    },
  };
}

/* =============================================================================================
 * Container image rule (T-001)
 * ========================================================================================== */

function imageReference(c: ArchitectureComponent, tech: ComponentTechnology): string {
  const fromEvidence = c.evidence.find((e) => e.detail?.reference !== undefined)?.detail?.reference;
  return fromEvidence ?? (tech.version === null ? tech.name : `${tech.name}:${tech.version}`);
}

/** Same wording as the V0.4 uncertainty recorded on build base images, so the two collapse into one limitation. */
const BUILD_IMAGE_NOTE = 'A build-time base image declared in a Dockerfile; this is not evidence of a running service.';

const imageTagRule: StrideRule = {
  id: 'STRIDE-T-001',
  category: 'Tampering',
  basis: 'observed',
  summary: 'A Dockerfile base image or compose service image has no tag or uses the tag "latest" (not for digest-pinned or variable references).',
  evaluate(ctx: RuleContext): RuleFinding[] {
    const findings: RuleFinding[] = [];
    for (const c of ctx.model.components.filter((x) => x.containerRole !== undefined).sort((a, b) => compare(a.id, b.id))) {
      const tech = sortedTechnologies(c).find((t) => t.kind === 'image');
      if (!tech) continue;
      const reference = imageReference(c, tech);
      if (/\$\{?\w/.test(reference)) {
        findings.push({
          kind: 'not-assessed',
          targetId: c.id,
          targetName: c.name,
          reason: 'The image reference uses a variable whose value is not resolved, so tag immutability cannot be assessed.',
        });
        continue;
      }
      if (/@sha256:/i.test(reference) || (tech.version ?? '').toLowerCase().startsWith('sha256:')) {
        continue; // pinned by digest: immutable
      }
      const implicitLatest = tech.version === null;
      if (!implicitLatest && tech.version!.toLowerCase() !== 'latest') {
        continue; // an explicit version tag
      }
      const isBuildImage = c.containerRole === 'build-base-image';
      findings.push({
        kind: 'threat',
        target: componentTarget(c),
        title: `Container image reference is mutable: ${reference}`,
        description: isBuildImage
          ? 'The Dockerfile starts from an image reference that does not select a fixed version. The content behind it can change between builds, so the resulting image may differ (or be altered upstream) without any change to this repository.'
          : 'The compose service uses an image reference that does not select a fixed version. The content behind it can change between pulls, so what runs may differ (or be altered upstream) without any change to this repository.',
        observations: [
          {
            statement: implicitLatest
              ? `Image reference "${reference}" has no tag; Docker treats this as "latest".`
              : `Image reference "${reference}" uses the tag "latest".`,
            evidence: cloneEvidence(c.evidence),
          },
        ],
        assumptions: [],
        limitations: unique([
          'Registry-side controls (image signing, immutable tags, mirrors) and CI pinning policies are not visible.',
          isBuildImage
            ? BUILD_IMAGE_NOTE
            : 'Whether this service actually runs, and where, is not verified; only its declaration is known.',
          ...c.uncertainty.filter((u) => !/variable/.test(u)),
        ]),
      });
    }
    return findings;
  },
};

/* =============================================================================================
 * Dependency supply-chain rules (T-002, T-003), aggregated per module and manifest
 * ========================================================================================== */

const VERSION_ASSESSED: readonly Ecosystem[] = ['Node.js', 'Python', 'Rust'];
// V0.3 notes meaning "not a registry version at all" (handled by T-003, or local).
const NON_VERSION_NOTE = /path dependency|git dependency|URL dependency|workspace|direct URL reference|non-registry|alias for/;
const GITHUB_SHORTHAND = /^[\w.-]+\/[\w.-]+(#.*)?$/;
const PINNED_COMMIT = /#[0-9a-f]{40}$/i;

function lacksVersionConstraint(tech: ComponentTechnology): boolean {
  if (!VERSION_ASSESSED.includes(tech.ecosystem) || NON_VERSION_NOTE.test(tech.notes ?? '')) {
    return false;
  }
  if (tech.version === null) return true;
  const v = tech.version.trim().toLowerCase();
  return v === '' || v === '*' || v === 'latest' || v === 'x';
}

/** Dependencies fetched from a git/URL source. `pinned` only when the declaration visibly fixes a full commit. */
function remoteSource(tech: ComponentTechnology): { how: string; pinned: boolean } | undefined {
  const notes = tech.notes ?? '';
  if (tech.ecosystem === 'Node.js' && tech.version !== null) {
    const v = tech.version;
    if (/^(git\+|git:|github:|gitlab:|bitbucket:|https?:\/\/)/i.test(v) || GITHUB_SHORTHAND.test(v)) {
      return { how: 'git/URL specifier', pinned: PINNED_COMMIT.test(v) };
    }
  }
  if (tech.ecosystem === 'Python' && /direct URL reference/.test(notes)) return { how: 'direct URL reference', pinned: false };
  if (tech.ecosystem === 'Rust' && /git dependency|URL dependency/.test(notes)) return { how: notes.includes('git') ? 'git dependency' : 'URL dependency', pinned: false };
  return undefined;
}

type ManifestDependencyMatch = { lib: ArchitectureComponent; tech: ComponentTechnology; detail: string };

function manifestRule(
  id: string,
  summary: string,
  matcher: (tech: ComponentTechnology) => string | undefined,
  describe: (count: number, source: string) => { title: string; description: string; limitations: string[] }
): StrideRule {
  return {
    id,
    category: 'Tampering',
    basis: 'observed',
    summary,
    evaluate(ctx: RuleContext): RuleFinding[] {
      const findings: RuleFinding[] = [];
      const modules = [...ctx.componentsOfType('Application'), ...ctx.componentsOfType('Unknown')].sort((a, b) => compare(a.id, b.id));
      const declaresDependency = ctx.relationshipsOfType('declares-dependency');
      for (const module of modules) {
        const bySource = new Map<string, ManifestDependencyMatch[]>();
        for (const lib of ctx.declaredLibraries(module.id)) {
          for (const tech of sortedTechnologies(lib)) {
            const detail = matcher(tech);
            if (detail !== undefined) {
              bySource.set(tech.source, [...(bySource.get(tech.source) ?? []), { lib, tech, detail }]);
            }
          }
        }
        for (const source of [...bySource.keys()].sort()) {
          const matches = bySource.get(source)!;
          const libIds = unique(matches.map((m) => m.lib.id)).sort();
          const text = describe(matches.length, source);
          findings.push({
            kind: 'threat',
            target: componentTarget(module),
            qualifier: source,
            title: text.title,
            description: text.description,
            relatedComponentIds: libIds,
            relatedRelationshipIds: declaresDependency
              .filter((r) => r.sourceId === module.id && libIds.includes(r.targetId))
              .map((r) => r.id)
              .sort(),
            observations: matches.map((m) => ({
              statement: `${m.tech.name} is declared as ${displayVersion(m.tech.version)} in ${m.tech.source} (${m.tech.category ?? 'dependencies'}): ${m.detail}.`,
              evidence: declarationEvidence(m.lib, m.tech),
            })),
            assumptions: [],
            limitations: text.limitations,
          });
        }
      }
      return findings;
    },
  };
}

const unpinnedDependenciesRule = manifestRule(
  'STRIDE-T-002',
  'A Node.js, Python or Rust manifest declares dependencies with no version constraint ("*", "latest", empty, or none). Java and Go are not assessed.',
  (tech) => (lacksVersionConstraint(tech) ? 'no version constraint' : undefined),
  (count, source) => ({
    title: `${count} ${count === 1 ? 'dependency' : 'dependencies'} without a version constraint in ${source}`,
    description:
      'These dependencies declare no version constraint, so installation can resolve to any available version, including a newer or altered release (tampering through the dependency supply chain).',
    limitations: [
      'Lockfiles are not read; a lockfile may pin the resolved versions.',
      'Whether the registry or a mirror enforces integrity checks is not visible.',
      'Java is not assessed (a missing version there usually means it is managed by a parent or BOM) and Go always records versions.',
    ],
  })
);

const remoteDependenciesRule = manifestRule(
  'STRIDE-T-003',
  'A manifest declares dependencies fetched from git or URL sources that are not visibly pinned to a full commit (Node.js, Python, Rust).',
  (tech) => {
    const remote = remoteSource(tech);
    return remote && !remote.pinned ? remote.how : undefined;
  },
  (count, source) => ({
    title: `${count} ${count === 1 ? 'dependency' : 'dependencies'} from non-registry sources in ${source}`,
    description:
      'Dependencies fetched directly from git or URLs are not covered by registry integrity checks, and a reference to a branch or tag can change content over time (tampering through the dependency supply chain).',
    limitations: [
      'For Python direct references and Rust git/URL dependencies the exact reference (branch, tag, commit) is not recorded, so pinning cannot be judged.',
      'Credentials embedded in specifiers are redacted by earlier milestones and are not part of this analysis.',
      'Lockfiles are not read; they may record the resolved commit.',
    ],
  })
);

/* =============================================================================================
 * Database rules (T-004, R-002, I-001)
 * ========================================================================================== */

interface DatabaseRuleConfig {
  id: string;
  category: StrideCategory;
  summary: string;
  title: (name: string) => string;
  description: string;
  assumptions: readonly string[];
}

function databaseRule(config: DatabaseRuleConfig): StrideRule {
  return {
    id: config.id,
    category: config.category,
    basis: 'assumption-dependent',
    summary: config.summary,
    evaluate(ctx: RuleContext): RuleFinding[] {
      return ctx.componentsOfType('Database').map((db): RuleFinding => ({
        kind: 'threat',
        target: componentTarget(db),
        title: config.title(db.name),
        description: config.description,
        observations: [
          {
            statement:
              `${db.name} is a Database component (certainty: ${db.certainty})` +
              (db.containerRole === 'compose-service' ? ', declared as a compose service.' : ', identified from a declared client library.'),
            evidence: cloneEvidence(db.evidence),
          },
        ],
        assumptions: [...config.assumptions],
        limitations: unique([
          ...db.uncertainty,
          'Database configuration (credentials, roles, encryption, auditing, network exposure) is not described by the scanned files.',
        ]),
      }));
    },
  };
}

/* =============================================================================================
 * External Service rules (S-002, I-003)
 * ========================================================================================== */

interface ExternalRuleConfig {
  id: string;
  category: StrideCategory;
  summary: string;
  title: (name: string) => string;
  description: (name: string) => string;
  assumptions: readonly string[];
  extraLimitation: string;
}

function externalServiceRule(config: ExternalRuleConfig): StrideRule {
  return {
    id: config.id,
    category: config.category,
    basis: 'assumption-dependent',
    summary: config.summary,
    evaluate(ctx: RuleContext): RuleFinding[] {
      return ctx.componentsOfType('External Service').map((svc): RuleFinding => ({
        kind: 'threat',
        target: componentTarget(svc),
        title: config.title(svc.name),
        description: config.description(svc.name),
        observations: [
          {
            statement: `${svc.name} is an External Service component (certainty: ${svc.certainty}), identified from declared client dependencies (${sortedTechnologies(svc).map(dependencyLabel).join(', ')}).`,
            evidence: cloneEvidence(svc.evidence),
          },
        ],
        assumptions: [...config.assumptions],
        limitations: unique([...svc.uncertainty, config.extraLimitation]),
      }));
    },
  };
}

/* =============================================================================================
 * Client-library relationship rules (I-002, D-002, E-002)
 * ========================================================================================== */

interface ClientLinkRuleConfig {
  id: string;
  category: StrideCategory;
  summary: string;
  targetTypes: ReadonlyArray<ArchitectureComponent['type']>;
  title: (libName: string, targetName: string) => string;
  description: (targetName: string) => string;
  assumptions: readonly string[];
  extraLimitation: string;
}

function clientLinkRule(config: ClientLinkRuleConfig): StrideRule {
  return {
    id: config.id,
    category: config.category,
    basis: 'assumption-dependent',
    summary: config.summary,
    evaluate(ctx: RuleContext): RuleFinding[] {
      const findings: RuleFinding[] = [];
      const declaresDependency = ctx.relationshipsOfType('declares-dependency');
      for (const rel of ctx.relationshipsOfType('client-library-for')) {
        const lib = ctx.component(rel.sourceId);
        const target = ctx.component(rel.targetId);
        if (!lib || !target) {
          findings.push({ kind: 'not-assessed', targetId: rel.id, targetName: rel.id, reason: 'An endpoint of this relationship is missing from the model.' });
          continue;
        }
        if (!config.targetTypes.includes(target.type)) continue;
        const tech = sortedTechnologies(lib)[0];
        findings.push({
          kind: 'threat',
          target: { kind: 'relationship', id: rel.id, name: `${lib.name} → ${target.name}` },
          title: config.title(lib.name, target.name),
          description: config.description(target.name),
          relatedComponentIds: [lib.id, target.id].sort(),
          relatedRelationshipIds: declaresDependency.filter((r) => r.targetId === lib.id).map((r) => r.id).sort(),
          observations: [
            {
              statement: `Library ${tech ? dependencyLabel(tech) : lib.name} is declared${tech ? ` in ${tech.source}` : ''}.`,
              evidence: cloneEvidence(lib.evidence),
            },
            {
              statement: `${lib.name} is a recognised client library for ${target.name} (${target.type}, certainty: ${target.certainty}).`,
              evidence: cloneEvidence(rel.evidence),
            },
          ],
          assumptions: [...config.assumptions],
          limitations: unique([
            'The model records that a client library is declared, not that the application connects to the target at runtime.',
            config.extraLimitation,
            ...target.uncertainty,
          ]),
        });
      }
      return findings;
    },
  };
}

/* =============================================================================================
 * The rule catalog (15 rules). Order is irrelevant: the analyzer sorts the output.
 * ========================================================================================== */

const BACKEND_REACHABLE = 'The backend is reachable by callers that are not fully trusted (not established by the model).';

export const STRIDE_RULES: readonly StrideRule[] = [
  controlAbsenceRule({
    id: 'STRIDE-S-001',
    category: 'Spoofing',
    summary: 'A Backend whose module declares no recognised authentication library (not assessed for Django and Hapi).',
    kind: 'authentication',
    label: 'authentication',
    title: (n) => `Caller authentication is not evident for ${n}`,
    description:
      'No recognised authentication library is declared for this module. If requests are accepted without authentication implemented elsewhere, a caller could present a false identity (spoofing). This is a candidate for review, not evidence that authentication is missing.',
    assumptions: [BACKEND_REACHABLE, 'Caller authentication is not implemented by code, middleware or infrastructure that this analysis cannot see.'],
    builtInFrameworks: FRAMEWORKS_WITH_BUILT_IN_ACCESS_CONTROL,
  }),
  externalServiceRule({
    id: 'STRIDE-S-002',
    category: 'Spoofing',
    summary: 'An External Service component inferred from a declared SDK/client dependency.',
    title: (n) => `Identity of the remote endpoint is not established for ${n}`,
    description: (n) =>
      `A client dependency for ${n} is declared. If the application reaches this service over a network without verifying the server's identity, an impersonated endpoint could be trusted (spoofing). Whether and how the service is called is not established.`,
    assumptions: [
      'The application communicates with this service over a network (not established by the model).',
      'Server identity (for example TLS certificate validation) is not verified by the SDK defaults or by code this analysis cannot see.',
    ],
    extraLimitation: 'TLS and endpoint configuration are not read.',
  }),
  imageTagRule,
  unpinnedDependenciesRule,
  remoteDependenciesRule,
  databaseRule({
    id: 'STRIDE-T-004',
    category: 'Tampering',
    summary: 'A Database component (inferred from a client library or declared as a compose database service).',
    title: (n) => `Integrity of data held by ${n} depends on access control that is not visible`,
    description:
      'A data store is declared or inferred. If principals other than the intended ones can write to it, stored data could be altered (tampering). Access control for the data store is not described by the scanned files.',
    assumptions: ['The data store holds data whose integrity matters to the application (not established by the model).', 'Write access is not restricted by configuration this analysis cannot see.'],
  }),
  controlAbsenceRule({
    id: 'STRIDE-R-001',
    category: 'Repudiation',
    summary: 'A Node.js or Rust Backend whose module declares no recognised logging library. Python, Java and Go are not assessed.',
    kind: 'logging',
    label: 'logging',
    title: (n) => `Security-relevant event logging is not evident for ${n}`,
    description:
      'No recognised logging library is declared for this module. If security-relevant actions are not recorded by other means, they might later be denied or be impossible to attribute (repudiation).',
    assumptions: [
      'Security-relevant actions (such as sign-in or data changes) occur in this backend (not established by the model).',
      'No audit trail is produced by console output, infrastructure logs or other means this analysis cannot see.',
    ],
    assessedEcosystems: ECOSYSTEMS_WITHOUT_STDLIB_LOGGING,
    notAssessedEcosystemReason: (e) => `${e} provides standard-library logging, so the absence of a logging library is not meaningful and is not assessed.`,
  }),
  databaseRule({
    id: 'STRIDE-R-002',
    category: 'Repudiation',
    summary: 'A Database component (inferred from a client library or declared as a compose database service).',
    title: (n) => `Attribution of changes to ${n} is not established`,
    description:
      'A data store is declared or inferred. If changes to it cannot be attributed to an accountable principal, actions on stored data might later be denied (repudiation). Auditing capability is not described by the scanned files.',
    assumptions: ['More than one principal can change the stored data (not established by the model).', 'No database auditing or application-level change log exists in configuration this analysis cannot see.'],
  }),
  databaseRule({
    id: 'STRIDE-I-001',
    category: 'Information Disclosure',
    summary: 'A Database component (inferred from a client library or declared as a compose database service).',
    title: (n) => `Confidentiality of data held by ${n} is not established`,
    description:
      'A data store is declared or inferred. If it holds sensitive data and access, backups or storage are not protected, data could be disclosed to unintended parties (information disclosure). Protection settings are not described by the scanned files.',
    assumptions: ['The data store holds sensitive data (not established by the model).', 'Access control and encryption at rest are not enforced by configuration this analysis cannot see.'],
  }),
  clientLinkRule({
    id: 'STRIDE-I-002',
    category: 'Information Disclosure',
    summary: 'A client-library-for relationship to a Database or External Service.',
    targetTypes: ['Database', 'External Service'],
    title: (lib, target) => `Confidentiality of data exchanged with ${target} via ${lib} is not established`,
    description: (target) =>
      `A client library for ${target} is declared. If the application uses it over a network without transport protection, exchanged data could be read in transit (information disclosure).`,
    assumptions: [
      'The application uses this library to communicate with the target over a network (not established by the model).',
      'Transport encryption is not enabled by configuration or defaults this analysis cannot see.',
    ],
    extraLimitation: 'Connection strings and TLS settings are not read.',
  }),
  externalServiceRule({
    id: 'STRIDE-I-003',
    category: 'Information Disclosure',
    summary: 'An External Service component inferred from a declared SDK/client dependency.',
    title: (n) => `Handling of credentials for ${n} is not established`,
    description: (n) =>
      `A client dependency for ${n} is declared. Such SDKs typically need credentials (API keys or tokens). If these are stored or logged unsafely, they could be disclosed (information disclosure). How credentials are supplied is not described by the scanned files.`,
    assumptions: ['The SDK requires credentials supplied by the application or its environment (not established by the model).', 'Credentials are not managed by a secrets facility this analysis cannot see.'],
    extraLimitation: 'Environment files and secret stores are deliberately not read.',
  }),
  controlAbsenceRule({
    id: 'STRIDE-D-001',
    category: 'Denial of Service',
    summary: 'A Backend whose module declares no recognised rate-limiting library.',
    kind: 'rate-limiting',
    label: 'rate-limiting',
    title: (n) => `Request-rate limiting is not evident for ${n}`,
    description:
      'No recognised rate-limiting library is declared for this module. If requests are not limited elsewhere, a client could exhaust capacity with excessive traffic (denial of service).',
    assumptions: [BACKEND_REACHABLE, 'Rate limiting is not applied by a gateway, proxy or code that this analysis cannot see.'],
  }),
  clientLinkRule({
    id: 'STRIDE-D-002',
    category: 'Denial of Service',
    summary: 'A client-library-for relationship to a Database or External Service.',
    targetTypes: ['Database', 'External Service'],
    title: (lib, target) => `Availability of ${target} may affect the application (via ${lib})`,
    description: (target) =>
      `If the application depends on ${target} for normal operation, its unavailability or slowness could degrade the application (denial of service). Timeout, retry and fallback behaviour is not described by the scanned files.`,
    assumptions: ['The application depends on the target for normal operation (not established by the model).', 'No timeouts, retries or fallbacks protect the application from the target being unavailable.'],
    extraLimitation: 'Resilience patterns in code are not visible.',
  }),
  controlAbsenceRule({
    id: 'STRIDE-E-001',
    category: 'Elevation of Privilege',
    summary: 'A Backend whose module declares no recognised authorization library (not assessed for Django and Hapi).',
    kind: 'authorization',
    label: 'authorization',
    title: (n) => `Authorization enforcement is not evident for ${n}`,
    description:
      'No recognised authorization library is declared for this module. If different callers have different permissions and access checks are not made elsewhere, a caller could gain access beyond what was intended (elevation of privilege).',
    assumptions: [
      'More than one privilege level or ownership rule exists in the application (not established by the model).',
      'Access checks are not implemented by code, middleware or infrastructure that this analysis cannot see.',
    ],
    builtInFrameworks: FRAMEWORKS_WITH_BUILT_IN_ACCESS_CONTROL,
  }),
  clientLinkRule({
    id: 'STRIDE-E-002',
    category: 'Elevation of Privilege',
    summary: 'A client-library-for relationship to a Database component.',
    targetTypes: ['Database'],
    title: (lib, target) => `Privilege scope of the account used to reach ${target} via ${lib} is not established`,
    description: (target) =>
      `If the application connects to ${target} with an account that has more privileges than it needs, a flaw in the application could be used to act beyond its intended scope (elevation of privilege). The account and its privileges are not described by the scanned files.`,
    assumptions: ['The application connects to this database using a database account (not established by the model).', 'That account holds more privileges than the application requires.'],
    extraLimitation: 'Database roles and grants are not visible.',
  }),
];
