import { createRequire } from 'node:module';

// The owner starts this exact preload before Node imports the original Journal.
// No supplied object or environment path can install output authority.
const require = createRequire(import.meta.url);
await require('./pricingOwnedOutput').admitV25FromInheritedOwner();
