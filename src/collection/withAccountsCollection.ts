import type { CollectionConfig, Field } from 'payload'
import { canWriteAccount } from '../lib/account-capability.js'

export type AccountsCollectionOptions = {
  usersCollectionSlug: string
  realm: string
}

/** Identity rows are managed only by the server-side binding APIs, including with overrideAccess. */
export function withAccountsCollection(
  incoming: Omit<CollectionConfig, 'fields'> & { fields?: Field[] },
  options: AccountsCollectionOptions,
): CollectionConfig {
  const names = [
    'identityKey',
    'initialBindingKey',
    'realm',
    'provider',
    'subject',
    'user',
    'status',
    'provenance',
    'linkedBy',
    'revokedBy',
    'revokedAt',
    'emailAtBinding',
  ]
  if (incoming.fields?.some((field) => 'name' in field && names.includes(field.name))) {
    throw new Error('Account identity fields cannot be overridden')
  }
  return {
    ...incoming,
    custom: { ...incoming.custom, ssoAccounts: options },
    admin: {
      useAsTitle: 'subject',
      defaultColumns: ['provider', 'subject', 'user', 'status'],
      ...incoming.admin,
    },
    access: {
      read: ({ req }) =>
        req.user?.collection === options.usersCollectionSlug
          ? { user: { equals: req.user.id } }
          : false,
      ...incoming.access,
      create: () => false,
      update: () => false,
      delete: () => false,
    },
    hooks: {
      ...incoming.hooks,
      beforeChange: [
        ({ req, context }) => {
          if (!canWriteAccount(req.payload, context)) {
            throw new Error('Use the server-side identity binding APIs')
          }
        },
        ...(incoming.hooks?.beforeChange || []),
      ],
      beforeDelete: [
        () => {
          throw new Error('Identity tombstones cannot be deleted; revoke the identity instead')
        },
      ],
    },
    fields: [
      {
        name: 'identityKey',
        type: 'text',
        required: true,
        unique: true,
        admin: { hidden: true },
      },
      {
        name: 'initialBindingKey',
        type: 'text',
        unique: true,
        admin: { hidden: true },
      },
      {
        name: 'realm',
        type: 'text',
        required: true,
        admin: { readOnly: true },
      },
      {
        name: 'provider',
        type: 'text',
        required: true,
        admin: { readOnly: true },
      },
      {
        name: 'subject',
        type: 'text',
        required: true,
        admin: { readOnly: true },
      },
      {
        name: 'user',
        type: 'relationship',
        relationTo: options.usersCollectionSlug,
        required: true,
        index: true,
        admin: { readOnly: true },
      },
      {
        name: 'status',
        type: 'select',
        options: ['active', 'revoked'],
        required: true,
        defaultValue: 'active',
        admin: { readOnly: true },
      },
      {
        name: 'provenance',
        type: 'select',
        options: ['signup', 'verified-email-bootstrap', 'server-link'],
        required: true,
        admin: { readOnly: true },
      },
      {
        name: 'linkedBy',
        type: 'text',
        required: true,
        admin: { readOnly: true },
      },
      { name: 'emailAtBinding', type: 'email', admin: { readOnly: true } },
      { name: 'revokedBy', type: 'text', admin: { readOnly: true } },
      { name: 'revokedAt', type: 'date', admin: { readOnly: true } },
      ...(incoming.fields || []),
    ],
  }
}

export const withAccountCollection = withAccountsCollection
