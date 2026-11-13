import { getPayload, Payload } from 'payload'
import config from '@/payload.config'

import { describe, it, beforeAll, expect } from 'vitest'

let payload: Payload

describe.skipIf(!process.env.DATABASE_URI)('API', () => {
  beforeAll(async () => {
    const payloadConfig = await config
    payload = await getPayload({ config: payloadConfig })
  })

  it('fetches admin users', async () => {
    const users = await payload.find({
      collection: 'adminUsers',
    })
    expect(users).toBeDefined()
  })

  it('fetches app users', async () => {
    const users = await payload.find({
      collection: 'appUsers',
    })
    expect(users).toBeDefined()
  })
})
