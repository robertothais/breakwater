import { z } from "zod";

const PclogParamsSchema = z.object({
  salt: z.coerce.number().int().positive(),
  ver: z.coerce.number().int().min(1),
  alg: z.coerce.number().int().min(0).max(2),
  valg: z.coerce.number().int().min(0),
  norsa: z.coerce.number().int().min(0).max(1),
  noenc: z.coerce.number().int().min(0).max(1),
  key: z.string(),
  uniq: z.string().min(1),
  utime: z.coerce.number().int().positive(),
  data: z.string().min(1),
});

type PclogParams = z.infer<typeof PclogParamsSchema>;

export function parseLooseQuery(queryString: string) {
  const params: Record<string, string> = {};
  for (const part of queryString.split("&")) {
    const i = part.indexOf("=");
    if (i === -1) params[part] = "";
    else params[part.slice(0, i)] = part.slice(i + 1);
  }
  return params;
}

export function parsePclogParams(queryString: string): PclogParams {
  return PclogParamsSchema.parse(parseLooseQuery(queryString));
}
