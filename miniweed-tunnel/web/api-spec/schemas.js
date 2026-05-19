const z = require('zod');

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const OptionalWireGuardKeySchema = z.union([z.string().regex(WG_KEY_RE), z.literal('')]).optional();
const OptionalEmailSchema = z.union([z.string().email(), z.literal('')]).optional();
const OptionalStringOrEmptySchema = z.union([z.string().min(1), z.literal('')]).optional();
const OptionalServiceNameSchema = z.union([z.string().min(1).max(64), z.literal('')]).optional();
const OptionalSubdomainSchema = z.union([z.string().regex(/^[a-z0-9-]{1,63}$/), z.literal('')]).optional();
const OptionalTargetSchema = z.union([z.string().regex(/^https?:\/\/[^\/\?#]+$/), z.literal('')]).optional();
const FailoverPolicySchema = z.object({
  activeFailuresRequired: z.number().int().min(1).max(10).optional(),
  candidateSuccessesRequired: z.number().int().min(1).max(10).optional(),
  cooldownMs: z.number().int().min(0).max(3_600_000).optional()
});

const ServiceSchema = z.object({
  name: OptionalServiceNameSchema,
  subdomain: OptionalSubdomainSchema,
  target: OptionalTargetSchema,
  enabled: z.boolean().optional()
});

const VpsTargetSchema = z.object({
  id: z.string().min(1).max(64).optional(),
  name: z.string().min(1).max(64).optional(),
  ip: OptionalStringOrEmptySchema,
  port: z.number().int().min(1).max(65535).optional(),
  pubKey: OptionalWireGuardKeySchema,
  enabled: z.boolean().optional(),
  priority: z.number().int().min(0).max(99).optional()
});

const ConfigSchema = z.object({
  vpsIp: OptionalStringOrEmptySchema,
  vpsPort: z.number().int().min(1).max(65535).optional(),
  vpsPubKey: OptionalWireGuardKeySchema,
  vpsTargets: z.array(VpsTargetSchema).max(8).optional(),
  activeVpsId: z.union([z.string().min(1).max(64), z.literal('')]).optional(),
  domain: z.string().optional(),
  acmeEmail: OptionalEmailSchema,
  failoverPolicy: FailoverPolicySchema.optional(),
  services: z.array(ServiceSchema).max(64).optional()
});

const AuthPasswordSchema = z.object({
  password: z.string().min(12).max(256)
});

const AuthLoginSchema = z.object({
  password: z.string().min(1).max(256)
});

const RotatePrepareSchema = z.object({
  nextPrivateKey: z.string().regex(WG_KEY_RE).optional(),
  nextPublicKey: z.string().regex(WG_KEY_RE).optional(),
  nextPresharedKey: z.string().regex(WG_KEY_RE).optional()
}).superRefine((value, ctx) => {
  const hasPrivate = Boolean(value.nextPrivateKey);
  const hasPublic = Boolean(value.nextPublicKey);
  if (hasPrivate !== hasPublic) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'nextPrivateKey and nextPublicKey must be provided together'
    });
  }
  if (value.nextPresharedKey && !(hasPrivate && hasPublic)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'nextPresharedKey requires nextPrivateKey and nextPublicKey'
    });
  }
});

const RotateConfirmSchema = z.object({
  planId: z.string().regex(/^[a-f0-9]{32}$/),
  apply: z.boolean().optional()
});

module.exports = {
  ServiceSchema,
  VpsTargetSchema,
  ConfigSchema,
  FailoverPolicySchema,
  AuthPasswordSchema,
  AuthLoginSchema,
  RotatePrepareSchema,
  RotateConfirmSchema
};
