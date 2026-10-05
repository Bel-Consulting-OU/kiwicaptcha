export type {
  StoreAdapter,
  ConsumedRecordSnapshot,
  ConsumedResultRecord,
  RuntimeKind,
  RuntimeStateSnapshot,
  DeleteIfPendingOutcome,
} from './store.js';
export {
  StoreUnavailableError,
  StoreWriteError,
  decodeEnvelope,
  validatedOperationIdentity,
  DEFAULT_TTL_MARGIN_SECS,
} from './store.js';
export { MemoryStore, type MemoryStoreOptions } from './stores/memory.js';
export { RedisStore, type RedisLike, type RedisStoreOptions } from './stores/redis.js';
export { SqliteStore, type SqliteLike, type SqliteStoreOptions } from './stores/sqlite.js';
export {
  verify,
  ladderRung,
  validateRecord,
  policyVersionAccepted,
  verifyRecordSignature,
  recomputeValidProof,
  resolveConsumedRecord,
  measurableSolveDurationMs,
  MAX_TTL_SECS,
  MAX_CLOCK_SKEW,
  SKEW_TOLERANCE_US,
  MIN_ARGON_MEMORY_KIB,
  MAX_ARGON_MEMORY_KIB,
  MIN_ARGON_TIME,
  MAX_ARGON_TIME,
  MIN_PARALLELISM,
  MAX_PARALLELISM,
  MIN_DIFFICULTY,
  MAX_DIFFICULTY,
  type VerifyOptions,
  type VerifyResult,
  type RswVerifierConfig,
} from './verify.js';
export {
  VerifyErrorCode,
  ALL_VERIFY_ERROR_CODES,
  describeVerifyError,
  isReplayExempt,
} from './errors.js';
export {
  derivedKeys,
  HKDF_DEPLOY_SALT,
  INFO_CHALLENGE_SIGN,
  INFO_IP_BIND,
  INFO_RESULT_TOKEN,
  INFO_SERVER_STATE,
  MIN_SECRET_BYTES,
  type DerivedKeys,
} from './keys.js';
export {
  serverStateKey,
  recordMetaMac,
  recordMetaInput,
  consumedResultMac,
  consumedResultInput,
  timingSafeEqualsHex,
  RECORD_META_DOMAIN,
  CONSUMED_RESULT_DOMAIN,
  SERVER_STATE_MAC_PATTERN,
} from './mac.js';
export {
  canonicalPayload,
  signedCanonicalCommitsRecordMeta,
  executionCommitment,
  hashIp,
  signPayloadV1,
  signPayloadV2,
  bindingTag,
  canonicalIpFamily,
  buffersEqual,
  POW_ALGORITHMS,
  type CanonicalPayloadArgs,
  type PowAlgorithm,
} from './canonical.js';
export {
  challengeRecordFromJson,
  challengeRecordToJson,
  isValidIdentifier,
  isValidDecoyFieldName,
  protocolExtensionGrammarOk,
  MalformedRecordError,
  MAX_PROTOCOL_VERSION,
  MAX_STRING_BYTES,
  MAX_EXECUTION_VERSION,
  MAX_PROGRAM_BASE64,
  type ChallengeRecord,
} from './record.js';
export {
  decodeToken,
  encodeToken,
  DecodeError,
  SOLVER_MAX_HASHES,
  MAX_DURATION_MS,
  type SolutionToken,
  type DecodeErrorCode,
} from './token.js';
export {
  leadingZeroBits,
  deriveSha256Hash,
  meetsTarget,
  solveSha256,
} from './pow.js';
export {
  Rsw,
  deriveBase,
  rswProofHex,
  modulusFingerprintHex,
  rswIdentityMatches,
  RSW_MODULUS_BYTES,
  RSW_PROOF_HEX_LENGTH,
  RSW_T_MIN,
  RSW_T_MAX,
} from './rsw.js';
export {
  decodeProgram,
  isValidProgram,
  verifyExecutedTrace,
  digestOverTrace,
  expectedDigest,
  canonicalTrace,
  EXECUTION_LABEL,
  EXECUTION_MAX_VERSION,
  EXECUTION_MAX_PROGRAM_BASE64,
  SRCDOC_URL_DIGEST,
  SRCDOC_PREEXISTING_BODY_ELEMENTS,
  TRACE_NAMES,
  ATTR_NAMES,
  OP_COUNT,
  type ExecutionProgram,
  type ExecutedOp,
} from './execution.js';
export { scoreTelemetry } from './telemetry.js';
export {
  KiwiOutcomes,
  OUTCOMES,
  OUTCOME_MAP_VERSION,
  HANDLE_DIMENSIONS,
  outcomeMapping,
  allOutcomeMappings,
  ledgerDimensions,
  identityDimensions,
  accepts,
  validateOutcomeHandle,
  markKind,
  hasLedgerAction,
  markKey,
  defaultIdempotencyKey,
  RISK_EVENT_KINDS,
  type Outcome,
  type OutcomeHandle,
  type OutcomeHandleDimension,
  type OutcomeMapping,
  type OutcomeReceipt,
  type OutcomeSink,
} from './outcomes.js';
export {
  kiwiVerifyExpress,
  DEFAULT_TOKEN_FIELD,
  type ExpressVerifyOptions,
} from './middleware/express.js';
export {
  kiwiVerifyFastify,
  DEFAULT_TOKEN_FIELD_FASTIFY,
  type FastifyVerifyOptions,
} from './middleware/fastify.js';
export { runDoctor, type DoctorCheck, type DoctorInput, type DoctorReport } from './doctor.js';
