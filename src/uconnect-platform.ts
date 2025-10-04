import { API, DynamicPlatformPlugin, Logger, PlatformAccessory, PlatformConfig, Service, Characteristic } from 'homebridge';
import { PLATFORM_NAME, PLUGIN_NAME, VEHICLE_BRANDS, VEHICLE_REGIONS, VehicleBrand, VehicleRegion, DEFAULT_CONFIG } from './settings';
import { UconnectPlatformAccessory } from './uconnect-accessory';
import { moparApi } from './mopar-api';

/**
 * HomebridgePlatform
 * This class is the main constructor for your plugin, this is where you should
 * parse the user config and discover/register accessories with Homebridge.
 */
export class UconnectHomebridgePlatform implements DynamicPlatformPlugin {
  public readonly Service: typeof Service = this.api.hap.Service;
  public readonly Characteristic: typeof Characteristic = this.api.hap.Characteristic;

  // this is used to track restored cached accessories
  public readonly accessories: PlatformAccessory[] = [];

  // Data from config
  public readonly username: string;
  public readonly password: string;
  public readonly pin: string;
  public readonly brand: VehicleBrand;
  public readonly region: VehicleRegion;
  public readonly timeout : number;
  public readonly useGuardian: boolean;

  constructor(
    public readonly log: Logger,
    public readonly config: PlatformConfig,
    public readonly api: API,
  ) {
    this.username = config.email;
    this.password = config.password;
    this.pin = config.pin || '';
    this.brand = (config.brand as VehicleBrand) || DEFAULT_CONFIG.brand;
    this.region = (config.region as VehicleRegion) || DEFAULT_CONFIG.region;
    this.timeout = config.timeout || DEFAULT_CONFIG.timeout;
    this.useGuardian = config.useGuardian || DEFAULT_CONFIG.useGuardian;

    this.log.debug('Finished initializing platform:', this.config.name);
    this.log.info(`Configured for ${VEHICLE_BRANDS[this.brand].name} in ${VEHICLE_REGIONS[this.region].name}`);
    if (this.useGuardian) {
      this.log.info('SiriusXM Guardian mode enabled');
    }

    // When this event is fired it means Homebridge has restored all cached accessories from disk.
    // Dynamic Platform plugins should only register new accessories after this event was fired,
    // in order to ensure they weren't added to homebridge already. This event can also be used
    // to start discovery of new accessories.
    this.api.on('didFinishLaunching', () => {
      log.debug('Executed didFinishLaunching callback');
      // run the method to discover / register your devices as accessories
      this.discoverDevices();
    });
  }

  /**
   * This function is invoked when homebridge restores cached accessories from disk at startup.
   * It should be used to setup event handlers for characteristics and update respective values.
   */
  configureAccessory(accessory: PlatformAccessory) {
    this.log.info('Loading accessory from cache:', accessory.displayName);

    // add the restored accessory to the accessories cache so we can track if it has already been registered
    this.accessories.push(accessory);
  }

  /**
   * This is an example method showing how to register discovered accessories.
   * Accessories must only be registered once, previously created accessories
   * must not be registered again to prevent "duplicate UUID" errors.
   */
  async discoverDevices() {
    this.log.info('Starting device discovery...');

    // Authenticate with retry logic
    this.log.info(`Authenticating with ${VEHICLE_BRANDS[this.brand].name}...`);
    try {
      if (! await moparApi.signIn(this.username, this.password, this.brand)) {
        this.log.error(`Failed to authenticate with ${VEHICLE_BRANDS[this.brand].name} after multiple attempts`);
        this.log.error('Please check your credentials and try again');
        return;
      }
      this.log.info(`Successfully authenticated with ${VEHICLE_BRANDS[this.brand].name}`);
    } catch (error) {
      this.log.error('Authentication error:', error instanceof Error ? error.message : String(error));
      this.log.error('Please check your credentials and try again');
      return;
    }
    const vehicles = await moparApi.getVehicleData();
    if (typeof(vehicles) === 'string') {
      this.log.error('Failed to retrieve vehicle list:', vehicles);
      return;
    }

    // loop over the discovered devices and register each one if it has not already been registered
    for (const vehicle of vehicles) {

      this.log.debug('Retrieved vehicle info:', vehicle);
      // generate a unique id for the accessory this should be generated from
      // something globally unique, but constant, for example, the device serial
      // number or MAC address
      const uuid = this.api.hap.uuid.generate(vehicle.vin);

      // see if an accessory with the same uuid has already been registered and restored from
      // the cached devices we stored in the `configureAccessory` method above
      const existingAccessory = this.accessories.find(accessory => accessory.UUID === uuid);

      if (existingAccessory) {
        // the accessory already exists
        this.log.info('Restoring existing accessory from cache:', existingAccessory.displayName);

        // if you need to update the accessory.context then you should run `api.updatePlatformAccessories`. eg.:
        // existingAccessory.context.device = device;
        // this.api.updatePlatformAccessories([existingAccessory]);

        // create the accessory handler for the restored accessory
        // this is imported from `platformAccessory.ts`
        new UconnectPlatformAccessory(this, existingAccessory);

        // it is possible to remove platform accessories at any time using `api.unregisterPlatformAccessories`, eg.:
        // remove platform accessories when no longer present
        // this.api.unregisterPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [existingAccessory]);
        // this.log.info('Removing existing accessory from cache:', existingAccessory.displayName);
      } else {
        // the accessory does not yet exist, so we need to create it
        this.log.info('Adding new accessory:', vehicle.title);

        // create a new accessory
        const accessory = new this.api.platformAccessory(vehicle.title, uuid);

        // store a copy of the device object in the `accessory.context`
        // the `context` property can be used to store any data about the accessory you may need
        accessory.context.vehicle = vehicle;

        // create the accessory handler for the newly create accessory
        // this is imported from `platformAccessory.ts`
        new UconnectPlatformAccessory(this, accessory);

        // link the accessory to your platform
        this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
      }
    }
  }
}
