import type { Payload, RequestContext } from 'payload'

const capabilities = new WeakMap<Payload, object>()

export function accountWriteContext(payload: Payload): RequestContext {
  let capability = capabilities.get(payload)
  if (!capability) {
    capability = Object.freeze({})
    capabilities.set(payload, capability)
  }
  return { ssoAccountCapability: capability }
}

export function canWriteAccount(payload: Payload, context: RequestContext): boolean {
  const capability = capabilities.get(payload)
  return Boolean(capability && context.ssoAccountCapability === capability)
}
