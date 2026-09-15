// zod-contract-auth: Security schemes + per-operation public override.
//
// Reads everything from plugin options, writes `components/securitySchemes`
// (its own output file) and injects `security:` into every `paths.{ext}` found
// in ctx.outputs that the build pipeline produced. Public routes (matched by
// OpenAPI path) drop `security:` entirely.

import { parse as parseYaml, stringify as yaml } from 'yaml'
import type { BuildContext, Plugin } from '@aemrezorlu/zod-contract'

export interface HttpBearerScheme {
  type: 'http'
  scheme: 'bearer'
  bearerFormat?: string
}
export interface HttpBasicScheme {
  type: 'http'
  scheme: 'basic'
}
export type HttpScheme = HttpBearerScheme | HttpBasicScheme

export interface ApiKeyScheme {
  type: 'apiKey'
  /** 'header' | 'query' | 'cookie' */
  in: 'header' | 'query' | 'cookie'
  /** Name of the header/param/cookie (e.g. 'X-API-Key'). */
  name: string
}

export type SecurityScheme = HttpScheme | ApiKeyScheme

export interface AuthPluginOptions {
  /** Named schemes the API supports. */
  schemes: Record<string, SecurityScheme>
  /** Security requirements.
   *  - `default`: applied to every operation unless it's public.
   *  - `public`: OpenAPI path strings to skip. Wildcard suffix supported (`/internal/*`). */
  require: {
    default: string[]
    public?: string[]
  }
  /** Filename for the securitySchemes file. Default: `components/securitySchemes.<ext>`. */
  outputPath?: string
}

export function authPlugin(opts: AuthPluginOptions): Plugin {
  if (!opts.schemes || Object.keys(opts.schemes).length === 0) {
    throw new Error('authPlugin: opts.schemes must contain at least one scheme')
  }
  return {
    name: 'auth',
    finalize(ctx: BuildContext): BuildContext {
      const out = outputPath(ctx.format, opts.outputPath)
      const componentName = pathBase(ctx.format, opts.outputPath)

      // 1) write components/securitySchemes.<ext>
      ctx.outputs.set(out, serializeComponents(opts.schemes, ctx.format))

      // 2) walk paths.{yaml,json} in ctx.outputs and inject security:
      for (const [rel, content] of [...ctx.outputs.entries()]) {
        if (!isPathsOutput(rel)) continue
        ctx.outputs.set(rel, injectSecurity(content, ctx.format, opts))
      }

      // ponytail: not appending root-level `security:` — that requires coordination with
      // the user's index.yaml. v0.2 may add an `indexSecurity: true` flag.
      void componentName
      return ctx
    },
  }
}

function outputPath(format: 'yaml' | 'json', custom?: string): string {
  if (custom) return custom
  return `components/securitySchemes.${format}`
}

function pathBase(_format: 'yaml' | 'json', custom?: string): string {
  if (custom) return custom.replace(/\.(yaml|json)$/, '')
  return 'components/securitySchemes'
}

function isPathsOutput(rel: string): boolean {
  return /(^|\/)paths\.(yaml|json)$/.test(rel)
}

function serializeComponents(
  schemes: Record<string, SecurityScheme>,
  format: 'yaml' | 'json',
): string {
  const components = { securitySchemes: schemes }
  return format === 'json' ? JSON.stringify(components, null, 2) + '\n' : yaml(components)
}

function injectSecurity(
  content: string,
  format: 'yaml' | 'json',
  opts: AuthPluginOptions,
): string {
  const doc = format === 'json' ? JSON.parse(content) : parseYaml(content)
  const paths = doc.paths as Record<string, Record<string, unknown>> | undefined
  if (!paths || typeof paths !== 'object') return content

  for (const [openapiPath, methods] of Object.entries(paths)) {
    if (!methods || typeof methods !== 'object') continue
    if (isPublic(openapiPath, opts.require.public ?? [])) continue
    for (const op of Object.values(methods)) {
      if (!op || typeof op !== 'object') continue
      ;(op as Record<string, unknown>).security = opts.require.default.map((name) => ({ [name]: [] }))
    }
  }
  return format === 'json' ? JSON.stringify(doc, null, 2) + '\n' : yaml(doc)
}

function isPublic(openapiPath: string, publicPatterns: string[]): boolean {
  for (const p of publicPatterns) {
    if (p === openapiPath) return true
    if (p.endsWith('/*') && openapiPath.startsWith(p.slice(0, -1))) return true
  }
  return false
}
