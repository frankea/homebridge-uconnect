/**
 * This is the name of the platform that users will use to register the plugin in the Homebridge config.json
 */
export const PLATFORM_NAME = 'Uconnect';

/**
 * This must match the name of your plugin as defined the package.json
 */
export const PLUGIN_NAME = 'homebridge-uconnect';

/**
 * Supported vehicle brands and their configuration
 */
export const VEHICLE_BRANDS = {
  jeep: { name: 'Jeep', connectUrl: 'https://connect.jeep.com' },
  fiat: { name: 'Fiat', connectUrl: 'https://connect.fiat.com' },
  ram: { name: 'Ram', connectUrl: 'https://connect.ramtrucks.com' },
  dodge: { name: 'Dodge', connectUrl: 'https://connect.dodge.com' },
  alfa_romeo: { name: 'Alfa Romeo', connectUrl: 'https://connect.alfaromeo.com' },
  chrysler: { name: 'Chrysler', connectUrl: 'https://connect.chrysler.com' },
  maserati: { name: 'Maserati', connectUrl: 'https://connect.maserati.com' },
} as const;

export type VehicleBrand = keyof typeof VEHICLE_BRANDS;

/**
 * Supported regions
 */
export const VEHICLE_REGIONS = {
  us: { name: 'United States', code: 'US' },
  ca: { name: 'Canada', code: 'CA' },
  eu: { name: 'Europe', code: 'EU' },
  asia: { name: 'Asia', code: 'ASIA' },
} as const;

export type VehicleRegion = keyof typeof VEHICLE_REGIONS;

/**
 * Default configuration values
 */
export const DEFAULT_CONFIG = {
  brand: 'jeep' as VehicleBrand,
  region: 'us' as VehicleRegion,
  timeout: 30,
  useGuardian: false,
} as const;