import type {NextConfig} from 'next';
const nextConfig:NextConfig={...(process.env.THREATLENS_LOCAL==='1'?{output:'standalone' as const,turbopack:{resolveAlias:{'cloudflare:workers':'./lib/portable-cloudflare.ts'}}}:{})};
export default nextConfig;
