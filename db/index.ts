import {env} from 'cloudflare:workers';
export function getDatabase():D1Database {
 if(!env.DB)throw new Error('Hosted storage is temporarily unavailable. Please try again.');
 return env.DB;
}
