const z = require('zod');

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;

const ServiceSchema = z.object({
  name: z.string().min(1).max(64),
  subdomain: z.string().regex(/^[a-z0-9-]{1,63}$/),
  target: z.string().regex(/^https?:\/\/[^\/\?#]+$/),
  enabled: z.boolean()
});

const VpsTargetSchema = z.object({
  id: z.string().min(1).max(64).optional(),
  name: z.string().min(1).max(64).optional(),
  ip: z.string().min(1),
  port: z.number().int().min(1).max(65535).optional(),
  pubKey: z.string().regex(WG_KEY_RE).optional(),
  enabled: z.boolean().optional(),
  priority: z.number().int().min(0).max(99).optional()
});

const ConfigSchema = z.object({
  vpsIp: z.string().min(1).optional(),
  vpsPort: z.number().int().min(1).max(65535).optional(),
  vpsPubKey: z.string().regex(WG_KEY_RE).optional(),
  vpsTargets: z.array(VpsTargetSchema).max(8).optional(),
  activeVpsId: z.string().min(1).max(64).optional(),
  domain: z.string().optional(),
  acmeEmail: z.string().email().optional(),
  services: z.array(ServiceSchema).max(64).optional()
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
  RotatePrepareSchema,
  RotateConfirmSchema
};
