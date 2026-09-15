# zod-contract-auth

Auth/security schemes + per-operation public override, as a plugin for
[`zod-contract`](https://www.npmjs.com/package/@aemrezorlu/zod-contract).

v0.1.x — supports `http` (Basic/Bearer) and `apiKey` schemes. OAuth2/OIDC
deferred to v0.2.

## Install

```bash
npm install --save-dev @aemrezorlu/zod-contract-auth
```

Peer dep: `@aemrezorlu/zod-contract` `^0.3.0`.

## Use

```ts
import { build } from '@aemrezorlu/zod-contract'
import { pathsPlugin } from '@aemrezorlu/zod-contract-paths'
import { authPlugin } from '@aemrezorlu/zod-contract-auth'

await build({
  src: 'src/api',
  out: 'api',
  plugins: [
    pathsPlugin({ routesDir: 'src/routes' }),
    authPlugin({
      schemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
        apiKeyAuth: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
      },
      require: {
        default: ['bearerAuth'],
        public: ['/health', '/ready', '/internal/*'],
      },
    }),
  ],
})
```

## Output

The plugin writes `components/securitySchemes.<ext>` and injects
`security:` into every `paths.<ext>` already in `ctx.outputs`.

```yaml
paths:
  /health:
    get: {}                    # public — no security
  /users:
    get:
      security: [{ bearerAuth: [] }]
  /internal/keys:
    get: {}                    # public (wildcard /internal/*)
  /admin/secrets:
    get:
      security: [{ bearerAuth: [] }]
```

```json
{
  "securitySchemes": {
    "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" },
    "apiKeyAuth": { "type": "apiKey", "in": "header", "name": "X-API-Key" }
  }
}
```

## Public override

`require.public` matches by OpenAPI path. Wildcard suffix supported:
`/internal/*` matches every path under `/internal/`.

## License

MIT
