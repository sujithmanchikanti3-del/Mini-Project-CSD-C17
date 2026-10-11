import { Ecosystem } from '../scanner/technology/types';

/** Identifiers of the deterministic rules; they appear in every piece of evidence. */
export const RULE_IDS = {
  workspaceRoot: 'workspace-root',
  projectManifest: 'project-manifest',
  manifestInSubdirectory: 'manifest-in-subdirectory',
  manifestDeclaresDependency: 'manifest-declares-dependency',
  runtimeTechnologyDeclaration: 'runtime-technology-declaration',
  dockerfileBaseImage: 'dockerfile-base-image',
  composeServiceImage: 'compose-service-image',
  composeDatabaseImage: 'compose-database-image',
  frontendFrameworkDependency: 'frontend-framework-dependency',
  backendFrameworkDependency: 'backend-framework-dependency',
  databaseClientLibrary: 'database-client-library',
  externalServiceSdk: 'external-service-sdk',
} as const;

/* ============================ dependency classification ============================ */

export type DependencyRole = 'frontend' | 'backend' | 'database-client' | 'external-service-sdk';

export interface DependencyRule {
  role: DependencyRole;
  /** Framework / database / service name used for the derived component ("React", "PostgreSQL", "Stripe"). */
  label: string;
  ecosystem: Ecosystem;
  /** Normalised package names that match exactly. */
  exact?: readonly string[];
  /** Normalised name prefixes that match. */
  prefix?: readonly string[];
}

/**
 * Curated, deliberately small. A match means "this declared dependency is a well-known X",
 * NOT "the application definitely uses X at runtime". To extend: add a line.
 * ORMs (sequelize, typeorm, prisma, sqlalchemy, hibernate) are NOT listed: they do not identify the database.
 */
export const DEPENDENCY_RULES: readonly DependencyRule[] = [
  // ---- Frontend frameworks ----
  { role: 'frontend', label: 'React', ecosystem: 'Node.js', exact: ['react', 'react-dom'] },
  { role: 'frontend', label: 'Vue', ecosystem: 'Node.js', exact: ['vue'] },
  { role: 'frontend', label: 'Angular', ecosystem: 'Node.js', exact: ['@angular/core'] },
  { role: 'frontend', label: 'Svelte', ecosystem: 'Node.js', exact: ['svelte'] },
  { role: 'frontend', label: 'Solid', ecosystem: 'Node.js', exact: ['solid-js'] },
  { role: 'frontend', label: 'Preact', ecosystem: 'Node.js', exact: ['preact'] },
  { role: 'frontend', label: 'Lit', ecosystem: 'Node.js', exact: ['lit'] },
  { role: 'frontend', label: 'Yew', ecosystem: 'Rust', exact: ['yew'] },
  { role: 'frontend', label: 'Leptos', ecosystem: 'Rust', exact: ['leptos'] },
  { role: 'frontend', label: 'Dioxus', ecosystem: 'Rust', exact: ['dioxus'] },

  // ---- Backend / server frameworks ----
  { role: 'backend', label: 'Express', ecosystem: 'Node.js', exact: ['express'] },
  { role: 'backend', label: 'Fastify', ecosystem: 'Node.js', exact: ['fastify'] },
  { role: 'backend', label: 'Koa', ecosystem: 'Node.js', exact: ['koa'] },
  { role: 'backend', label: 'Hapi', ecosystem: 'Node.js', exact: ['@hapi/hapi'] },
  { role: 'backend', label: 'NestJS', ecosystem: 'Node.js', exact: ['@nestjs/core'] },
  { role: 'backend', label: 'Restify', ecosystem: 'Node.js', exact: ['restify'] },
  { role: 'backend', label: 'Flask', ecosystem: 'Python', exact: ['flask'] },
  { role: 'backend', label: 'Django', ecosystem: 'Python', exact: ['django'] },
  { role: 'backend', label: 'FastAPI', ecosystem: 'Python', exact: ['fastapi'] },
  { role: 'backend', label: 'Starlette', ecosystem: 'Python', exact: ['starlette'] },
  { role: 'backend', label: 'Tornado', ecosystem: 'Python', exact: ['tornado'] },
  { role: 'backend', label: 'Sanic', ecosystem: 'Python', exact: ['sanic'] },
  { role: 'backend', label: 'Spring Web', ecosystem: 'Java', prefix: ['org.springframework.boot:spring-boot-starter-web'] },
  { role: 'backend', label: 'Ktor', ecosystem: 'Java', exact: ['io.ktor:ktor-server-core'] },
  { role: 'backend', label: 'Javalin', ecosystem: 'Java', exact: ['io.javalin:javalin'] },
  { role: 'backend', label: 'Micronaut', ecosystem: 'Java', prefix: ['io.micronaut:micronaut-http-server'] },
  { role: 'backend', label: 'Gin', ecosystem: 'Go', exact: ['github.com/gin-gonic/gin'] },
  { role: 'backend', label: 'Echo', ecosystem: 'Go', prefix: ['github.com/labstack/echo'] },
  { role: 'backend', label: 'Fiber', ecosystem: 'Go', prefix: ['github.com/gofiber/fiber'] },
  { role: 'backend', label: 'Chi', ecosystem: 'Go', prefix: ['github.com/go-chi/chi'] },
  { role: 'backend', label: 'Gorilla Mux', ecosystem: 'Go', exact: ['github.com/gorilla/mux'] },
  { role: 'backend', label: 'Actix Web', ecosystem: 'Rust', exact: ['actix-web'] },
  { role: 'backend', label: 'Axum', ecosystem: 'Rust', exact: ['axum'] },
  { role: 'backend', label: 'Rocket', ecosystem: 'Rust', exact: ['rocket'] },
  { role: 'backend', label: 'Warp', ecosystem: 'Rust', exact: ['warp'] },

  // ---- Database client libraries / drivers (label = the database they talk to) ----
  { role: 'database-client', label: 'PostgreSQL', ecosystem: 'Node.js', exact: ['pg', 'pg-promise', 'postgres'] },
  { role: 'database-client', label: 'MySQL', ecosystem: 'Node.js', exact: ['mysql', 'mysql2'] },
  { role: 'database-client', label: 'MongoDB', ecosystem: 'Node.js', exact: ['mongodb', 'mongoose'] },
  { role: 'database-client', label: 'Redis', ecosystem: 'Node.js', exact: ['redis', 'ioredis'] },
  { role: 'database-client', label: 'SQLite', ecosystem: 'Node.js', exact: ['sqlite3', 'better-sqlite3'] },
  { role: 'database-client', label: 'SQL Server', ecosystem: 'Node.js', exact: ['mssql', 'tedious'] },
  { role: 'database-client', label: 'PostgreSQL', ecosystem: 'Python', exact: ['psycopg2', 'psycopg2-binary', 'psycopg', 'asyncpg'] },
  { role: 'database-client', label: 'MySQL', ecosystem: 'Python', exact: ['pymysql', 'mysqlclient', 'mysql-connector-python'] },
  { role: 'database-client', label: 'MongoDB', ecosystem: 'Python', exact: ['pymongo', 'motor'] },
  { role: 'database-client', label: 'Redis', ecosystem: 'Python', exact: ['redis'] },
  { role: 'database-client', label: 'PostgreSQL', ecosystem: 'Java', exact: ['org.postgresql:postgresql'] },
  { role: 'database-client', label: 'MySQL', ecosystem: 'Java', exact: ['mysql:mysql-connector-java', 'com.mysql:mysql-connector-j'] },
  { role: 'database-client', label: 'MongoDB', ecosystem: 'Java', prefix: ['org.mongodb:'] },
  { role: 'database-client', label: 'SQLite', ecosystem: 'Java', exact: ['org.xerial:sqlite-jdbc'] },
  { role: 'database-client', label: 'H2', ecosystem: 'Java', exact: ['com.h2database:h2'] },
  { role: 'database-client', label: 'PostgreSQL', ecosystem: 'Go', exact: ['github.com/lib/pq'], prefix: ['github.com/jackc/pgx'] },
  { role: 'database-client', label: 'MySQL', ecosystem: 'Go', exact: ['github.com/go-sql-driver/mysql'] },
  { role: 'database-client', label: 'MongoDB', ecosystem: 'Go', prefix: ['go.mongodb.org/mongo-driver'] },
  { role: 'database-client', label: 'Redis', ecosystem: 'Go', exact: ['github.com/go-redis/redis'], prefix: ['github.com/redis/go-redis'] },
  { role: 'database-client', label: 'PostgreSQL', ecosystem: 'Rust', exact: ['tokio-postgres', 'postgres'] },
  { role: 'database-client', label: 'MySQL', ecosystem: 'Rust', exact: ['mysql', 'mysql-async'] },
  { role: 'database-client', label: 'Redis', ecosystem: 'Rust', exact: ['redis'] },
  { role: 'database-client', label: 'SQLite', ecosystem: 'Rust', exact: ['rusqlite'] },
  { role: 'database-client', label: 'MongoDB', ecosystem: 'Rust', exact: ['mongodb'] },

  // ---- External service SDKs (label = the service) ----
  { role: 'external-service-sdk', label: 'Stripe', ecosystem: 'Node.js', exact: ['stripe'] },
  { role: 'external-service-sdk', label: 'AWS', ecosystem: 'Node.js', exact: ['aws-sdk'], prefix: ['@aws-sdk/'] },
  { role: 'external-service-sdk', label: 'SendGrid', ecosystem: 'Node.js', prefix: ['@sendgrid/'] },
  { role: 'external-service-sdk', label: 'Twilio', ecosystem: 'Node.js', exact: ['twilio'] },
  { role: 'external-service-sdk', label: 'Firebase', ecosystem: 'Node.js', exact: ['firebase', 'firebase-admin'] },
  { role: 'external-service-sdk', label: 'Slack', ecosystem: 'Node.js', prefix: ['@slack/'] },
  { role: 'external-service-sdk', label: 'OpenAI', ecosystem: 'Node.js', exact: ['openai'] },
  { role: 'external-service-sdk', label: 'Anthropic', ecosystem: 'Node.js', exact: ['@anthropic-ai/sdk'] },
  { role: 'external-service-sdk', label: 'Google Cloud', ecosystem: 'Node.js', prefix: ['@google-cloud/'] },
  { role: 'external-service-sdk', label: 'Azure', ecosystem: 'Node.js', prefix: ['@azure/'] },
  { role: 'external-service-sdk', label: 'AWS', ecosystem: 'Python', exact: ['boto3', 'botocore'] },
  { role: 'external-service-sdk', label: 'Stripe', ecosystem: 'Python', exact: ['stripe'] },
  { role: 'external-service-sdk', label: 'Twilio', ecosystem: 'Python', exact: ['twilio'] },
  { role: 'external-service-sdk', label: 'OpenAI', ecosystem: 'Python', exact: ['openai'] },
  { role: 'external-service-sdk', label: 'Anthropic', ecosystem: 'Python', exact: ['anthropic'] },
  { role: 'external-service-sdk', label: 'Google Cloud', ecosystem: 'Python', prefix: ['google-cloud-'] },
  { role: 'external-service-sdk', label: 'Azure', ecosystem: 'Python', prefix: ['azure-'] },
  { role: 'external-service-sdk', label: 'Slack', ecosystem: 'Python', exact: ['slack-sdk', 'slack-bolt'] },
  { role: 'external-service-sdk', label: 'SendGrid', ecosystem: 'Python', exact: ['sendgrid'] },
  { role: 'external-service-sdk', label: 'AWS', ecosystem: 'Java', prefix: ['com.amazonaws:', 'software.amazon.awssdk:'] },
  { role: 'external-service-sdk', label: 'Stripe', ecosystem: 'Java', exact: ['com.stripe:stripe-java'] },
  { role: 'external-service-sdk', label: 'Google Cloud', ecosystem: 'Java', prefix: ['com.google.cloud:'] },
  { role: 'external-service-sdk', label: 'Azure', ecosystem: 'Java', prefix: ['com.azure:'] },
  { role: 'external-service-sdk', label: 'AWS', ecosystem: 'Go', prefix: ['github.com/aws/aws-sdk-go'] },
  { role: 'external-service-sdk', label: 'Stripe', ecosystem: 'Go', prefix: ['github.com/stripe/stripe-go'] },
  { role: 'external-service-sdk', label: 'Google Cloud', ecosystem: 'Go', prefix: ['cloud.google.com/go'] },
  { role: 'external-service-sdk', label: 'AWS', ecosystem: 'Rust', prefix: ['aws-sdk-'] },
];

/**
 * Dependency categories that never trigger a role classification (the library component still exists).
 * Rationale: a test/dev/build-only dependency says little about what the application IS; indirect
 * (transitive) dependencies were not chosen by the project; a peer dependency is supplied by the
 * consumer, so declaring "react" as a peer marks a library/plugin, not a frontend.
 */
const NON_ROLE_BEARING_CATEGORY =
  /^(devDependencies|peerDependencies|dev-dependencies|dev-packages|build-dependencies|build-system|test\w*|androidTestImplementation|debugImplementation|require \(indirect\)|plugin-dependency|dependencyManagement|classpath|annotationProcessor|kapt|ksp|parent|(optional-dependencies|dependency-groups|group):.*|target\..*\.(dev|build)-dependencies)$/i;

export function isRoleBearingCategory(category: string): boolean {
  return !NON_ROLE_BEARING_CATEGORY.test(category);
}

/** Case-insensitive; for Python also PEP 503 normalisation (Flask == flask, psycopg2_binary == psycopg2-binary). */
export function normalizePackageName(ecosystem: Ecosystem, name: string): string {
  const lower = name.toLowerCase();
  return ecosystem === 'Python' ? lower.replace(/[-_.]+/g, '-') : lower;
}

export function matchDependencyRule(dep: { name: string; ecosystem: Ecosystem; category: string }): DependencyRule | undefined {
  if (!isRoleBearingCategory(dep.category)) {
    return undefined;
  }
  const name = normalizePackageName(dep.ecosystem, dep.name);
  return DEPENDENCY_RULES.find(
    (rule) =>
      rule.ecosystem === dep.ecosystem &&
      ((rule.exact?.includes(name) ?? false) || (rule.prefix?.some((p) => name.startsWith(p)) ?? false))
  );
}

/* ============================ container image classification ============================ */

const DATABASE_IMAGE_LABELS: ReadonlyMap<string, string> = new Map([
  ['postgres', 'PostgreSQL'],
  ['postgresql', 'PostgreSQL'],
  ['mysql', 'MySQL'],
  ['mariadb', 'MariaDB'],
  ['mongo', 'MongoDB'],
  ['mongodb', 'MongoDB'],
  ['redis', 'Redis'],
  ['cassandra', 'Cassandra'],
  ['couchdb', 'CouchDB'],
  ['neo4j', 'Neo4j'],
  ['influxdb', 'InfluxDB'],
  ['memcached', 'Memcached'],
  ['cockroach', 'CockroachDB'],
  ['cockroachdb', 'CockroachDB'],
]);

/** Database technology name if the image repository (e.g. "bitnami/postgresql", "redis") is a well-known database image. */
export function databaseLabelForImage(repository: string): string | undefined {
  const lower = repository.toLowerCase();
  if (lower === 'mssql/server' || lower.endsWith('/mssql/server')) {
    return 'SQL Server'; // not "mssql-tools" and other client/tool images
  }
  return DATABASE_IMAGE_LABELS.get(lower.slice(lower.lastIndexOf('/') + 1));
}
