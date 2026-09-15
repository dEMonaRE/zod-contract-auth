import { describe, it, expect } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { authPlugin } from '../src/auth-plugin.js'
import type { BuildContext } from '@aemrezorlu/zod-contract'

const PATHS_YAML = `paths:
  /health:
    get:
      summary: ok
  /users:
    get:
      summary: list
  /internal/keys:
    get:
      summary: keys
`

const PATHS_JSON = JSON.stringify(
  {
    paths: {
      '/health': { get: { summary: 'ok' } },
      '/users': { get: { summary: 'list' } },
      '/internal/keys': { get: { summary: 'keys' } },
    },
  },
  null,
  2,
) + '\n'

function makeCtx(format: 'yaml' | 'json' = 'yaml', withPaths = true): BuildContext {
  const ctx: BuildContext = {
    schemas: [],
    outputs: new Map<string, string>(),
    format,
    openapiVersion: '3.2.0',
  }
  if (withPaths) {
    ctx.outputs.set(format === 'json' ? 'paths.json' : 'paths.yaml', format === 'json' ? PATHS_JSON : PATHS_YAML)
  }
  return ctx
}

describe('zod-contract-auth', () => {
  it('throws on empty schemes', () => {
    expect(() => authPlugin({ schemes: {}, require: { default: [] } })).toThrow(/schemes/)
  })

  it('writes components/securitySchemes.yaml/json', async () => {
    const plugin = authPlugin({
      schemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      },
      require: { default: ['bearerAuth'] },
    })
    const yamlCtx = makeCtx('yaml')
    await plugin.finalize!(yamlCtx)
    expect(yamlCtx.outputs.has('components/securitySchemes.yaml')).toBe(true)

    const jsonCtx = makeCtx('json')
    await plugin.finalize!(jsonCtx)
    expect(jsonCtx.outputs.has('components/securitySchemes.json')).toBe(true)
  })

  it('injects security: into every non-public operation', async () => {
    const plugin = authPlugin({
      schemes: { bearerAuth: { type: 'http', scheme: 'bearer' } },
      require: { default: ['bearerAuth'], public: ['/health'] },
    })
    const ctx = makeCtx()
    await plugin.finalize!(ctx)
    const parsed = parseYaml(ctx.outputs.get('paths.yaml')!) as {
      paths: Record<string, Record<string, { security?: Array<Record<string, unknown>> }>>
    }
    expect(parsed.paths['/health'].get.security).toBeUndefined()
    expect(parsed.paths['/users'].get.security).toEqual([{ bearerAuth: [] }])
    expect(parsed.paths['/internal/keys'].get.security).toEqual([{ bearerAuth: [] }])
  })

  it('supports wildcard public suffix (*)', async () => {
    const plugin = authPlugin({
      schemes: { apiKeyAuth: { type: 'apiKey', in: 'header', name: 'X-API-Key' } },
      require: { default: ['apiKeyAuth'], public: ['/internal/*'] },
    })
    const ctx = makeCtx()
    await plugin.finalize!(ctx)
    const parsed = parseYaml(ctx.outputs.get('paths.yaml')!) as {
      paths: Record<string, Record<string, { security?: unknown }>>
    }
    expect(parsed.paths['/internal/keys'].get.security).toBeUndefined()
    expect(parsed.paths['/users'].get.security).toEqual([{ apiKeyAuth: [] }])
  })

  it('emits securitySchemes with apiKey and Bearer fields', async () => {
    const plugin = authPlugin({
      schemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        apiKeyAuth: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
      },
      require: { default: ['bearerAuth'] },
    })
    const ctx = makeCtx()
    await plugin.finalize!(ctx)
    const parsed = parseYaml(ctx.outputs.get('components/securitySchemes.yaml')!) as {
      securitySchemes: Record<string, unknown>
    }
    expect(parsed.securitySchemes.bearerAuth).toEqual({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' })
    expect(parsed.securitySchemes.apiKeyAuth).toEqual({ type: 'apiKey', in: 'header', name: 'X-API-Key' })
  })

  it('gracefully no-ops when paths output is missing', async () => {
    const plugin = authPlugin({
      schemes: { bearerAuth: { type: 'http', scheme: 'bearer' } },
      require: { default: ['bearerAuth'] },
    })
    const ctx = makeCtx('yaml', false)
    await plugin.finalize!(ctx)
    // Only securitySchemes output, no paths mutation attempted
    expect(ctx.outputs.has('components/securitySchemes.yaml')).toBe(true)
    expect(ctx.outputs.has('paths.yaml')).toBe(false)
  })

  it('honors custom outputPath', async () => {
    const plugin = authPlugin({
      schemes: { bearerAuth: { type: 'http', scheme: 'bearer' } },
      require: { default: ['bearerAuth'] },
      outputPath: 'auth.yaml',
    })
    const ctx = makeCtx()
    await plugin.finalize!(ctx)
    expect(ctx.outputs.has('auth.yaml')).toBe(true)
    expect(ctx.outputs.has('components/securitySchemes.yaml')).toBe(false)
  })
})
