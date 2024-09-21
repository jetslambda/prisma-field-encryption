import {
  cloakedStringRegex,
  CloakKeychain,
  decryptStringSync,
  encryptStringSync,
  findKeyForMessage,
  makeKeychainSync,
  ParsedCloakKey,
  parseKeySync
} from '@47ng/cloak'
import { Draft, produce } from 'immer'
import objectPath from 'object-path'
import { debug } from './debugger'
import type { DMMFModels } from './dmmf'
import { errors, warnings } from './errors'
import { hashString } from './hash'
import type { Configuration, MiddlewareParams } from './types'
import { visitInputTargetFields, visitOutputTargetFields } from './visitor'

let kms: any
let getKmsKey: any

export interface KeysConfiguration {
  encryptionKey: ParsedCloakKey
  keychain: CloakKeychain
  useKms?: boolean
  kmsKeyId?: string
  keyStrategy?: 'perTable' | 'perTenant'
  kmsKeyMappingTable?: string
}

export function configureKeys(config: Configuration): KeysConfiguration {
  const encryptionKey =
    config.encryptionKey || process.env.PRISMA_FIELD_ENCRYPTION_KEY

  if (!encryptionKey) {
    throw new Error(errors.noEncryptionKey)
  }

  const decryptionKeysFromEnv = (process.env.PRISMA_FIELD_DECRYPTION_KEYS ?? '')
    .split(',')
    .filter(Boolean)

  const decryptionKeys: string[] = Array.from(
    new Set([
      encryptionKey,
      ...(config.decryptionKeys ?? decryptionKeysFromEnv)
    ])
  )

  const keychain = makeKeychainSync(decryptionKeys)

  const useKms = config.useKms || process.env.PRISMA_FIELD_ENCRYPTION_USE_KMS === 'true'
  const kmsKeyId = useKms ? (config.kmsKeyId || process.env.PRISMA_FIELD_ENCRYPTION_KMS_KEY_ID) : undefined
  const keyStrategy = useKms ? (config.keyStrategy || process.env.PRISMA_FIELD_ENCRYPTION_KEY_STRATEGY) : undefined

  if (keyStrategy && !['perTable', 'perTenant'].includes(keyStrategy)) {
    throw new Error(`Invalid key strategy: ${keyStrategy}. Must be 'perTable' or 'perTenant'.`)
  }

  const kmsKeyMappingTable = config.kmsKeyMappingTable || process.env.PRISMA_FIELD_ENCRYPTION_KMS_KEY_MAPPING_TABLE

  if (useKms) {
    const { KMS } = require('aws-sdk')
    kms = new KMS()

    getKmsKey = async (keyId: string, cache: Map<string, string>) => {
      if (cache.has(keyId)) {
        return cache.get(keyId)!
      }

      const { Plaintext } = await kms.decrypt({
        KeyId: keyId,
        CiphertextBlob: Buffer.from(keyId, 'base64')
      }).promise()

      const key = Plaintext!.toString('base64')
      cache.set(keyId, key)
      return key
    }
  }

  return {
    encryptionKey: parseKeySync(encryptionKey),
    keychain,
    useKms,
    kmsKeyId,
    keyStrategy,
    kmsKeyMappingTable
  }
}

async function getKmsKeyFromMappingTable(
  client: any,
  keys: KeysConfiguration,
  model: string,
  tenantId?: string
): Promise<string | undefined> {
  if (!keys.kmsKeyMappingTable) {
    return undefined
  }

  const where = keys.keyStrategy === 'perTenant'
    ? { tenantId }
    : { tableName: model }

  const result = await client[keys.kmsKeyMappingTable].findFirst({
    where,
    select: { kmsKeyId: true }
  })

  return result?.kmsKeyId
}

export async function encryptOnWrite<Models extends string, Actions extends string>(
  params: MiddlewareParams<Models, Actions>,
  keys: KeysConfiguration,
  models: DMMFModels,
  operation: string
) {
  if (keys.useKms) {
    return encryptOnWriteKMS(params, keys, models, operation)
  }
  debug.encryption('Clear-text input: %O', params)
  const encryptionErrors: string[] = []
  const kmsKeyCache = new Map<string, string>()

  const mutatedParams = produce(
    params,
    async (draft: Draft<MiddlewareParams<Models, Actions>>) => {
      await visitInputTargetFields(
        draft, 
        models,
        async function encryptFieldValue({
          fieldConfig,
          value: clearText,
          path,
          model,
          field
        }) {
          const hashedPath = rewriteHashedFieldPath(
            path,
            field,
            fieldConfig.hash?.targetField ?? field + 'Hash'
          )
          if (hashedPath) {
            if (!fieldConfig.hash) {
              console.warn(warnings.whereConnectClauseNoHash(operation, path))
            } else {
              const hash = hashString(clearText, fieldConfig.hash)
              debug.encryption(
                `Swapping encrypted search of ${model}.${field} with hash search under ${fieldConfig.hash.targetField} (hash: ${hash})`
              )
              objectPath.del(draft.args, path)
              objectPath.set(draft.args, hashedPath, hash)
              return
            }
          }
          if (isOrderBy(path, field, clearText)) {
            // Remove unsupported orderBy clause on encrypted text
            // (makes no sense to sort ciphertext nor to encrypt 'asc' | 'desc')
            console.error(errors.orderByUnsupported(model, field))
            debug.encryption(
              `Removing orderBy clause on ${model}.${field} at path \`${path}: ${clearText}\``
            )
            objectPath.del(draft.args, path)
            return
          }
          if (!fieldConfig.encrypt) {
            return
          }

          let kmsKey: string | undefined
          if (keys.useKms && keys.kmsKeyId) {
            if (keys.keyStrategy === 'perTable') {
              kmsKey = await getKmsKeyFromMappingTable(draft.client, keys, model)
            } else if (keys.keyStrategy === 'perTenant' && fieldConfig.tenantIdField) {
              const tenantId = objectPath.get(draft.args, fieldConfig.tenantIdField) as string
              kmsKey = await getKmsKeyFromMappingTable(draft.client, keys, model, tenantId)
            } else {
              kmsKey = await getKmsKey(keys.kmsKeyId, kmsKeyCache)
            }
          }

          try {
            const cipherText = kmsKey 
              ? encryptStringSync(clearText, parseKeySync(kmsKey))
              : encryptStringSync(clearText, keys.encryptionKey)
            
            objectPath.set(draft.args, path, cipherText)

            if (kmsKey) {
              // Store encrypted key
              const keyId = Buffer.from(kmsKey, 'base64').toString('base64')
              objectPath.set(draft.args, `${path}KeyId`, keyId)
            }

            debug.encryption(`Encrypted ${model}.${field} at path \`${path}\``)
            
            if (fieldConfig.hash) {
              const hash = hashString(clearText, fieldConfig.hash)
              const hashPath = rewriteWritePath(
                path,
                field,
                fieldConfig.hash.targetField
              )
              objectPath.set(draft.args, hashPath, hash)
              debug.encryption(
                `Added hash ${hash} of ${model}.${field} under ${fieldConfig.hash.targetField}`
              )
            }
          } catch (error) {
            encryptionErrors.push(
              errors.fieldEncryptionError(model, field, path, error)  
            )
          }
        }
      )
    }
  )
  if (encryptionErrors.length > 0) {
    throw new Error(errors.encryptionErrorReport(operation, encryptionErrors))
  }
  debug.encryption('Encrypted input: %O', mutatedParams)
  return mutatedParams
}

async function encryptOnWriteKMS<Models extends string, Actions extends string>(
  params: MiddlewareParams<Models, Actions>,
  keys: KeysConfiguration,
  models: DMMFModels,
  operation: string
) {
  debug.encryption('Clear-text input: %O', params)
  const encryptionErrors: string[] = []
  const kmsKeyCache = new Map<string, string>()

  const mutatedParams = produce(
    params,
    async (draft: Draft<MiddlewareParams<Models, Actions>>) => {
      await visitInputTargetFields(
        draft, 
        models,
        async function encryptFieldValue({
          fieldConfig,
          value: clearText,
          path,
          model,
          field
        }) {
          const hashedPath = rewriteHashedFieldPath(
            path,
            field,
            fieldConfig.hash?.targetField ?? field + 'Hash'
          )
          if (hashedPath) {
            if (!fieldConfig.hash) {
              console.warn(warnings.whereConnectClauseNoHash(operation, path))
            } else {
              const hash = hashString(clearText, fieldConfig.hash)
              debug.encryption(
                `Swapping encrypted search of ${model}.${field} with hash search under ${fieldConfig.hash.targetField} (hash: ${hash})`
              )
              objectPath.del(draft.args, path)
              objectPath.set(draft.args, hashedPath, hash)
              return
            }
          }
          if (isOrderBy(path, field, clearText)) {
            // Remove unsupported orderBy clause on encrypted text
            // (makes no sense to sort ciphertext nor to encrypt 'asc' | 'desc')
            console.error(errors.orderByUnsupported(model, field))
            debug.encryption(
              `Removing orderBy clause on ${model}.${field} at path \`${path}: ${clearText}\``
            )
            objectPath.del(draft.args, path)
            return
          }
          if (!fieldConfig.encrypt) {
            return
          }

          let kmsKey: string | undefined
          if (keys.useKms && keys.kmsKeyId) {
            if (keys.keyStrategy === 'perTable') {
              kmsKey = await getKmsKeyFromMappingTable(draft.client, keys, model)
            } else if (keys.keyStrategy === 'perTenant' && fieldConfig.tenantIdField) {
              const tenantId = objectPath.get(draft.args, fieldConfig.tenantIdField) as string
              kmsKey = await getKmsKeyFromMappingTable(draft.client, keys, model, tenantId)
            } else {
              kmsKey = await getKmsKey(keys.kmsKeyId, kmsKeyCache)
            }
          }

          try {
            const cipherText = kmsKey 
              ? encryptStringSync(clearText, parseKeySync(kmsKey))
              : encryptStringSync(clearText, keys.encryptionKey)
            
            objectPath.set(draft.args, path, cipherText)

            if (kmsKey) {
              // Store encrypted key
              const keyId = Buffer.from(kmsKey, 'base64').toString('base64')
              objectPath.set(draft.args, `${path}KeyId`, keyId)
            }

            debug.encryption(`Encrypted ${model}.${field} at path \`${path}\``)
            
            if (fieldConfig.hash) {
              const hash = hashString(clearText, fieldConfig.hash)
              const hashPath = rewriteWritePath(
                path,
                field,
                fieldConfig.hash.targetField
              )
              objectPath.set(draft.args, hashPath, hash)
              debug.encryption(
                `Added hash ${hash} of ${model}.${field} under ${fieldConfig.hash.targetField}`
              )
            }
          } catch (error) {
            encryptionErrors.push(
              errors.fieldEncryptionError(model, field, path, error)  
            )
          }
        }
      )
    }
  )
  if (encryptionErrors.length > 0) {
    throw new Error(errors.encryptionErrorReport(operation, encryptionErrors))
  }
  debug.encryption('Encrypted input: %O', mutatedParams)
  return mutatedParams
}

export async function decryptOnRead<Models extends string, Actions extends string>(
  params: MiddlewareParams<Models, Actions>, 
  result: any,
  keys: KeysConfiguration,
  models: DMMFModels,
  operation: string
) {
  if (keys.useKms) {
    return decryptOnReadKMS(params, result, keys, models, operation)
  }
  // Analyse the query to see if there's anything to decrypt.
  const model = models[params.model!]
  if (
    Object.keys(model.fields).length === 0 &&
    !params.args?.include &&
    !params.args?.select
  ) {
    // The queried model doesn't have any encrypted field,
    // and there are no included connections.
    // We can safely skip decryption for the returned data.
    // todo: Walk the include/select tree for a better decision.
    debug.decryption(
      `Skipping decryption: ${params.model} has no encrypted field and no connection was included`
    )
    return
  }

  debug.decryption('Raw result from database: %O', result)

  const decryptionErrors: string[] = []
  const fatalDecryptionErrors: string[] = []

  const kmsKeyCache = new Map<string, string>()

  await visitOutputTargetFields(
    params,
    result, 
    models,
    async function decryptFieldValue({
      fieldConfig, 
      value: cipherText,
      path,
      model, 
      field
    }) {
      try {
        if (!cloakedStringRegex.test(cipherText)) {
          return
        }

        let decryptionKey = findKeyForMessage(cipherText, keys.keychain)

        if (keys.useKms) {
          const keyId = objectPath.get(result, `${path}KeyId`) as string | undefined
          if (keyId) {
            // Decrypt using KMS key
            decryptionKey = parseKeySync(await getKmsKey(keyId, kmsKeyCache))
          }
        }

        const clearText = decryptStringSync(cipherText, decryptionKey)
        objectPath.set(result, path, clearText)
        
        debug.decryption(
          `Decrypted ${model}.${field} at path \`${path}\` using key fingerprint ${decryptionKey.fingerprint}`
        )
      } catch (error) {
        const message = errors.fieldDecryptionError(model, field, path, error)
        if (fieldConfig.strictDecryption) {
          fatalDecryptionErrors.push(message)
        } else {
          decryptionErrors.push(message)
        }
      }
    }
  )
  if (decryptionErrors.length > 0) {
    console.error(errors.decryptionErrorReport(operation, decryptionErrors))
  }
  if (fatalDecryptionErrors.length > 0) {
    throw new Error(
      errors.decryptionErrorReport(operation, fatalDecryptionErrors)
    )
  }
  debug.decryption('Decrypted result: %O', result)
}

async function decryptOnReadKMS<Models extends string, Actions extends string>(
  params: MiddlewareParams<Models, Actions>, 
  result: any,
  keys: KeysConfiguration,
  models: DMMFModels,
  operation: string
) {
  // Analyse the query to see if there's anything to decrypt.
  const model = models[params.model!]
  if (
    Object.keys(model.fields).length === 0 &&
    !params.args?.include &&
    !params.args?.select
  ) {
    // The queried model doesn't have any encrypted field,
    // and there are no included connections.
    // We can safely skip decryption for the returned data.
    // todo: Walk the include/select tree for a better decision.
    debug.decryption(
      `Skipping decryption: ${params.model} has no encrypted field and no connection was included`
    )
    return
  }

  debug.decryption('Raw result from database: %O', result)

  const decryptionErrors: string[] = []
  const fatalDecryptionErrors: string[] = []

  const kmsKeyCache = new Map<string, string>()

  await visitOutputTargetFields(
    params,
    result, 
    models,
    async function decryptFieldValue({
      fieldConfig, 
      value: cipherText,
      path,
      model, 
      field
    }) {
      try {
        if (!cloakedStringRegex.test(cipherText)) {
          return
        }

        let decryptionKey = findKeyForMessage(cipherText, keys.keychain)

        if (keys.useKms) {
          const keyId = objectPath.get(result, `${path}KeyId`) as string | undefined
          if (keyId) {
            // Decrypt using KMS key
            decryptionKey = parseKeySync(await getKmsKey(keyId, kmsKeyCache))
          }
        }

        const clearText = decryptStringSync(cipherText, decryptionKey)
        objectPath.set(result, path, clearText)
        
        debug.decryption(
          `Decrypted ${model}.${field} at path \`${path}\` using key fingerprint ${decryptionKey.fingerprint}`
        )
      } catch (error) {
        const message = errors.fieldDecryptionError(model, field, path, error)
        if (fieldConfig.strictDecryption) {
          fatalDecryptionErrors.push(message)
        } else {
          decryptionErrors.push(message)
        }
      }
    }
  )
  if (decryptionErrors.length > 0) {
    console.error(errors.decryptionErrorReport(operation, decryptionErrors))
  }
  if (fatalDecryptionErrors.length > 0) {
    throw new Error(
      errors.decryptionErrorReport(operation, fatalDecryptionErrors)
    )
  }
  debug.decryption('Decrypted result: %O', result)
}

function rewriteHashedFieldPath(
  path: string,
  field: string,
  hashField: string
) {
  const items = path.split('.').reverse()
  // Special case for `where field equals or not` clause
  if (items.includes('where') && items[1] === field && ['equals', 'not'].includes(items[0])) {
    items[1] = hashField
    return items.reverse().join('.')
  }
  const clauses = ['where', 'connect', 'cursor']
  for (const clause of clauses) {
    if (items.includes(clause) && items[0] === field) {
      items[0] = hashField
      return items.reverse().join('.')
    }
  }
  return null
}

function rewriteWritePath(path: string, field: string, hashField: string) {
  const items = path.split('.').reverse()
  if (items[0] === field) {
    items[0] = hashField
  } else if (items[0] === 'set' && items[1] === field) {
    items[1] = hashField
  }
  return items.reverse().join('.')
}

function isOrderBy(path: string, field: string, value: string) {
  const items = path.split('.').reverse()
  return (
    items.includes('orderBy') &&
    items[0] === field &&
    ['asc', 'desc'].includes(value.toLowerCase())
  )
}
