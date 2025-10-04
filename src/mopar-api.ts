import axios, { AxiosInstance, AxiosResponse, Method } from 'axios';
import { wrapper } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';
import aws4 from 'aws4';
import { randomUUID } from 'crypto';
import { CognitoIdentityClient, GetCredentialsForIdentityCommand } from '@aws-sdk/client-cognito-identity';

import { VehicleBrand, VehicleRegion } from './settings';

interface BrandApiConfig {
  url: string;
  key: string;
}

interface BrandAuthConfig {
  url: string;
  token: string;
}

interface BrandConfig {
  name: string;
  region: string;
  loginApiKey: string;
  loginUrl: string;
  tokenUrl: string;
  api: BrandApiConfig;
  auth: BrandAuthConfig;
  locale: string;
}

const BRAND_CONFIGS: Record<string, BrandConfig> = {
  FIAT_EU: {
    name: 'FIAT_EU',
    region: 'eu-west-1',
    loginApiKey: '3_mOx_J2dRgjXYCdyhchv3b5lhi54eBcdCTX4BI8MORqmZCoQWhA0mV2PTlptLGUQI',
    loginUrl: 'https://loginmyuconnect.fiat.com',
    tokenUrl: 'https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-01.fcagcv.com',
      key: '2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i',
    },
    auth: {
      url: 'https://mfa.fcl-01.fcagcv.com',
      token: 'JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys',
    },
    locale: 'de_de',
  },
  FIAT_US: {
    name: 'FIAT_US',
    region: 'us-east-1',
    loginApiKey: '3_WfFvlZJwcSdOD0LFQCngUV3W390R4Yshpuq3RsZvnV4VG0c9Q6R0RtDwcXc8dTrI',
    loginUrl: 'https://login-us.fiat.com',
    tokenUrl: 'https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-02.fcagcv.com',
      key: 'OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU',
    },
    auth: {
      url: 'https://mfa.fcl-02.fcagcv.com',
      token: 'fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci',
    },
    locale: 'en_us',
  },
  FIAT_ASIA: {
    name: 'FIAT_ASIA',
    region: 'eu-west-1',
    loginApiKey: '4_YAQNaPqdPEUbbzhvhunKAA',
    loginUrl: 'https://login-iap.fiat.com',
    tokenUrl: 'https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-01.fcagcv.com',
      key: '2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i',
    },
    auth: {
      url: 'https://mfa.fcl-01.fcagcv.com',
      token: 'JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys',
    },
    locale: 'de_de',
  },
  FIAT_CANADA: {
    name: 'FIAT_CANADA',
    region: 'us-east-1',
    loginApiKey: '3_Ii2kSgQm4ljy19LIZeLwa76OlmWbpSa8w3aSP5VJdx19tub3oWxsFR-HEusDnUEh',
    loginUrl: 'https://login-stage-us.fiat.com',
    tokenUrl: 'https://authz.sdpr-02.prep.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-02.fcagcv.com',
      key: 'OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU',
    },
    auth: {
      url: 'https://mfa.fcl-02.prep.fcagcv.com',
      token: 'lHBEtsqT1Y5oKvzhvA9KW6rkirU3ZtGf44jTIiQV',
    },
    locale: 'en_us',
  },
  ALFA_ROMEO_US_CANADA: {
    name: 'ALFA_ROMEO_US_CANADA',
    region: 'us-east-1',
    loginApiKey: '3_FSxGyaktviayTDRcgp9r9o2KjuFSrHT13wWNN9zPrvAGUCoXPDqoIPOwlBUhck4A',
    loginUrl: 'https://login-us.alfaromeo.com',
    tokenUrl: 'https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-02.fcagcv.com',
      key: 'OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU',
    },
    auth: {
      url: 'https://mfa.fcl-02.fcagcv.com',
      token: 'fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci',
    },
    locale: 'en_us',
  },
  ALFA_ROMEO_ASIA: {
    name: 'ALFA_ROMEO_ASIA',
    region: 'eu-west-1',
    loginApiKey: '4_PSQeADnQ4p5XOaDgT0B5pA',
    loginUrl: 'https://login-iap.alfaromeo.com',
    tokenUrl: 'https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-01.fcagcv.com',
      key: '2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i',
    },
    auth: {
      url: 'https://mfa.fcl-01.fcagcv.com',
      token: 'JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys',
    },
    locale: 'de_de',
  },
  ALFA_ROMEO_EU: {
    name: 'ALFA_ROMEO_EU',
    region: 'eu-west-1',
    loginApiKey: '3_h8sj2VQI-KYXiunPq9a1QuAA4yWkY0r5AD1u8A8B1RPn_Cvl54xcoc2-InH5onJ1',
    loginUrl: 'https://login.alfaromeo.com',
    tokenUrl: 'https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-01.fcagcv.com',
      key: '2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i',
    },
    auth: {
      url: 'https://mfa.fcl-01.fcagcv.com',
      token: 'JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys',
    },
    locale: 'de_de',
  },
  CHRYSLER_CANADA: {
    name: 'CHRYSLER_CANADA',
    region: 'us-east-1',
    loginApiKey: '3_gdhu-ur4jc2hEryDMnF4YPELkjzSi-invZTjop4isZu4ReHodVcuL44u93cOUqMC',
    loginUrl: 'https://login-stage-us.chrysler.com',
    tokenUrl: 'https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-02.fcagcv.com',
      key: 'OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU',
    },
    auth: {
      url: 'https://mfa.fcl-02.fcagcv.com',
      token: 'fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci',
    },
    locale: 'en_us',
  },
  CHRYSLER_US: {
    name: 'CHRYSLER_US',
    region: 'us-east-1',
    loginApiKey: '3_cv4AzHkJh48-cqwaf_Ahcg1HnsmQqz1lm0sOdVdHW5FjT3m6SyywywOBaskBQqwn',
    loginUrl: 'https://login-us.chrysler.com',
    tokenUrl: 'https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-02.fcagcv.com',
      key: 'OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU',
    },
    auth: {
      url: 'https://mfa.fcl-02.fcagcv.com',
      token: 'fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci',
    },
    locale: 'en_us',
  },
  MASERATI_EU: {
    name: 'MASERATI_EU',
    region: 'eu-west-1',
    loginApiKey: '3_rNbVuhn2gIt3BnLjlGsJcMo26Lft3avDne_FLRT34Dy_9OxHtCVOnplwY436lGZa',
    loginUrl: 'https://login.maserati.com',
    tokenUrl: 'https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-01.fcagcv.com',
      key: '2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i',
    },
    auth: {
      url: 'https://mfa.fcl-01.fcagcv.com',
      token: 'JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys',
    },
    locale: 'de_de',
  },
  MASERATI_ASIA: {
    name: 'MASERATI_ASIA',
    region: 'eu-west-1',
    loginApiKey: '4_uwF-in6KF-aMbEkPAb-fOg',
    loginUrl: 'https://accounts.au1.gigya.com',
    tokenUrl: 'https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-01.fcagcv.com',
      key: '2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i',
    },
    auth: {
      url: 'https://mfa.fcl-01.fcagcv.com',
      token: 'JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys',
    },
    locale: 'de_de',
  },
  MASERATI_US_CANADA: {
    name: 'MASERATI_US_CANADA',
    region: 'us-east-1',
    loginApiKey: '3_nShL4-O7IL0OGqroO8AzwiRU0-ZHcBZ4TLBrh5MORusMo5XYxhCLXPYfjI4OOLOy',
    loginUrl: 'https://login-us.maserati.com',
    tokenUrl: 'https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-02.fcagcv.com',
      key: 'OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU',
    },
    auth: {
      url: 'https://mfa.fcl-02.fcagcv.com',
      token: 'fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci',
    },
    locale: 'en_us',
  },
  JEEP_EU: {
    name: 'JEEP_EU',
    region: 'eu-west-1',
    loginApiKey: '3_ZvJpoiZQ4jT5ACwouBG5D1seGEntHGhlL0JYlZNtj95yERzqpH4fFyIewVMmmK7j',
    loginUrl: 'https://login.jeep.com',
    tokenUrl: 'https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-01.fcagcv.com',
      key: '2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i',
    },
    auth: {
      url: 'https://mfa.fcl-01.fcagcv.com',
      token: 'JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys',
    },
    locale: 'de_de',
  },
  JEEP_US: {
    name: 'JEEP_US',
    region: 'us-east-1',
    loginApiKey: '3_5qxvrevRPG7--nEXe6huWdVvF5kV7bmmJcyLdaTJ8A45XUYpaR398QNeHkd7EB1X',
    loginUrl: 'https://login-us.jeep.com',
    tokenUrl: 'https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-02.fcagcv.com',
      key: 'OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU',
    },
    auth: {
      url: 'https://mfa.fcl-02.fcagcv.com',
      token: 'fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci',
    },
    locale: 'en_us',
  },
  JEEP_ASIA: {
    name: 'JEEP_ASIA',
    region: 'eu-west-1',
    loginApiKey: '4_zqGYHC7rM8RCHHl4YFDebA',
    loginUrl: 'https://login-iap.jeep.com',
    tokenUrl: 'https://authz.sdpr-01.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-01.fcagcv.com',
      key: '2wGyL6PHec9o1UeLPYpoYa1SkEWqeBur9bLsi24i',
    },
    auth: {
      url: 'https://mfa.fcl-01.fcagcv.com',
      token: 'JWRYW7IYhW9v0RqDghQSx4UcRYRILNmc8zAuh5ys',
    },
    locale: 'de_de',
  },
  DODGE_US: {
    name: 'DODGE_US',
    region: 'us-east-1',
    loginApiKey: '4_dSRvo6ZIpp8_St7BF9VHGA',
    loginUrl: 'https://login-us.dodge.com',
    tokenUrl: 'https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-02.fcagcv.com',
      key: 'OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU',
    },
    auth: {
      url: 'https://mfa.fcl-02.fcagcv.com',
      token: 'fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci',
    },
    locale: 'en_us',
  },
  RAM_US: {
    name: 'RAM_US',
    region: 'us-east-1',
    loginApiKey: '3_7YjzjoSb7dYtCP5-D6FhPsCciggJFvM14hNPvXN9OsIiV1ujDqa4fNltDJYnHawO',
    loginUrl: 'https://login-us.ramtrucks.com',
    tokenUrl: 'https://authz.sdpr-02.fcagcv.com/v2/cognito/identity/token',
    api: {
      url: 'https://channels.sdpr-02.fcagcv.com',
      key: 'OgNqp2eAv84oZvMrXPIzP8mR8a6d9bVm1aaH9LqU',
    },
    auth: {
      url: 'https://mfa.fcl-02.fcagcv.com',
      token: 'fNQO6NjR1N6W0E5A6sTzR3YY4JGbuPv48Nj9aZci',
    },
    locale: 'en_us',
  },
};

const BRAND_REGION_MAP: Record<VehicleBrand, Partial<Record<VehicleRegion, keyof typeof BRAND_CONFIGS>>> = {
  jeep: { us: 'JEEP_US', ca: 'JEEP_US', eu: 'JEEP_EU', asia: 'JEEP_ASIA' },
  fiat: { us: 'FIAT_US', ca: 'FIAT_CANADA', eu: 'FIAT_EU', asia: 'FIAT_ASIA' },
  ram: { us: 'RAM_US', ca: 'RAM_US' },
  dodge: { us: 'DODGE_US', ca: 'DODGE_US' },
  alfa_romeo: { us: 'ALFA_ROMEO_US_CANADA', ca: 'ALFA_ROMEO_US_CANADA', eu: 'ALFA_ROMEO_EU', asia: 'ALFA_ROMEO_ASIA' },
  chrysler: { us: 'CHRYSLER_US', ca: 'CHRYSLER_CANADA' },
  maserati: { us: 'MASERATI_US_CANADA', ca: 'MASERATI_US_CANADA', eu: 'MASERATI_EU', asia: 'MASERATI_ASIA' },
};

export type RequestStatus = 'INITIATED' | 'SUCCESS' | 'FAILURE' | 'TIMEOUT' | 'UNKNOWN';
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

type SignedRequestBase = 'api' | 'auth';

interface SignedRequestConfig {
  base: SignedRequestBase;
  method: Method;
  path: string;
  query?: Record<string, unknown>;
  body?: unknown;
  headers?: Record<string, string>;
}

interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: Date;
}

interface VehicleInfo {
  vin: string;
  title: string;
  make: string;
  model: string;
  year: string;
}

interface RawVehicle {
  vin?: string;
  vehicle?: {
    vin?: string;
  };
  make?: string;
  brand?: string;
  modelDescription?: string;
  model?: string;
  tsoModelYear?: string | number;
  year?: string | number;
  modelYear?: string | number;
  nickname?: string;
  vehicleNickname?: string;
}

interface VehiclesResponse {
  vehicles?: RawVehicle[];
}

interface CommandResponse {
  responseStatus?: string;
  correlationId?: string;
  debugMsg?: string;
}

interface NotificationsEnvelope {
  items?: NotificationItem[];
}

interface NotificationsResponse {
  notifications?: NotificationsEnvelope;
}

interface NotificationItem {
  correlationId?: string;
  notification?: {
    data?: {
      status?: string;
    };
  };
}

interface PinAuthResponse {
  token?: string;
}

type BrandKey = keyof typeof BRAND_CONFIGS;

class MoparApi {
  private axiosInstance: AxiosInstance;
  private jar: CookieJar;
  private cognitoClient?: CognitoIdentityClient;
  private credentials?: AwsCredentials;
  private uid?: string;
  private brandKey?: BrandKey;
  private brandConfig?: BrandConfig;
  private username?: string;
  private password?: string;
  private region?: VehicleRegion;

  constructor() {
    const { client, jar } = this.createHttpClient();
    this.axiosInstance = client;
    this.jar = jar;
  }

  async signIn(username: string, password: string, brand: VehicleBrand, region: VehicleRegion): Promise<void> {
    const brandKey = resolveBrandKey(brand, region);

    if (this.isSessionValid(username, password, brandKey, region)) {
      return;
    }

    this.username = username;
    this.password = password;
    this.brandKey = brandKey;
    this.brandConfig = BRAND_CONFIGS[brandKey];
    this.region = region;
    this.uid = undefined;
    this.credentials = undefined;

    const { client, jar } = this.createHttpClient();
    this.axiosInstance = client;
    this.jar = jar;

    if (!this.cognitoClient || this.cognitoClient.config.region !== this.brandConfig.region) {
      this.cognitoClient = new CognitoIdentityClient({ region: this.brandConfig.region });
    }

    await this.performLogin();
  }

  async ensureAuthenticated(): Promise<void> {
    if (!this.username || !this.password || !this.brandKey || !this.region) {
      throw new Error('Not signed in');
    }

    if (!this.isSessionValid(this.username, this.password, this.brandKey, this.region)) {
      await this.signIn(this.username, this.password, mapBrandKeyToVehicleBrand(this.brandKey), this.region);
    }
  }

  async getVehicles(): Promise<VehicleInfo[]> {
    await this.ensureAuthenticated();
    if (!this.uid || !this.brandConfig) {
      throw new Error('Authentication state is invalid');
    }

    const response = await this.signedRequest<VehiclesResponse>({
      base: 'api',
      method: 'GET',
      path: `/v4/accounts/${this.uid}/vehicles`,
      query: { stage: 'ALL' },
    });

    const vehicles: VehicleInfo[] = [];
    const parsedVehicles: RawVehicle[] = [];
    const items = response.data?.vehicles;
    if (Array.isArray(items)) {
      parsedVehicles.push(...items as RawVehicle[]);
    } else if (items && typeof items === 'object') {
      parsedVehicles.push(...Object.values(items as Record<string, RawVehicle>));
    }

    if (parsedVehicles.length === 0 && response.data && typeof response.data === 'object') {
      for (const value of Object.values(response.data)) {
        if (Array.isArray(value)) {
          parsedVehicles.push(...value as RawVehicle[]);
        }
      }
    }

    if (parsedVehicles.length === 0) {
      return [];
    }

    for (const item of parsedVehicles) {
      const vin = item?.vin ?? item?.vehicle?.vin;
      if (!vin) {
        continue;
      }
      const make = sanitizeString(item?.make) || sanitizeString(item?.brand) || 'Unknown';
      const model = sanitizeString(item?.modelDescription) || sanitizeString(item?.model) || '';
      const yearValue = item?.tsoModelYear ?? item?.year ?? item?.modelYear;
      const year = yearValue ? String(yearValue) : '';
      const nickname = sanitizeString(item?.nickname) || sanitizeString(item?.vehicleNickname);
      const defaultTitle = [year, make, model].filter(Boolean).join(' ').trim();
      const title = nickname || defaultTitle || vin;
      vehicles.push({ vin, title, make, model: model || defaultTitle || 'Vehicle', year });
    }

    return vehicles;
  }

  async lockCar(vin: string, pin: string): Promise<string> {
    return this.executeCommand(vin, 'RDL', pin);
  }

  async unlockCar(vin: string, pin: string): Promise<string> {
    return this.executeCommand(vin, 'RDU', pin);
  }

  async startCar(vin: string, pin: string): Promise<string> {
    return this.executeCommand(vin, 'REON', pin);
  }

  async stopCar(vin: string, pin: string): Promise<string> {
    return this.executeCommand(vin, 'REOFF', pin);
  }

  async checkCommandStatus(vin: string, correlationId: string, timeoutSeconds: number): Promise<RequestStatus> {
    await this.ensureAuthenticated();

    const endTime = Date.now() + timeoutSeconds * 1000;
    let lastStatus: RequestStatus = 'INITIATED';

    while (Date.now() < endTime) {
      await delay(2000);
      const status = await this.fetchCommandStatus(vin, correlationId);
      if (!status) {
        continue;
      }
      lastStatus = status;
      if (status === 'SUCCESS' || status === 'FAILURE') {
        return status;
      }
    }

    return lastStatus === 'INITIATED' ? 'TIMEOUT' : lastStatus;
  }

  async getVehicleNotifications(vin: string): Promise<NotificationItem[]> {
    await this.ensureAuthenticated();

    const response = await this.signedRequest<NotificationsResponse>({
      base: 'api',
      method: 'GET',
      path: `/v1/accounts/${this.uid}/vehicles/${vin}/notifications`,
      query: { limit: 30 },
    });

    const items = response.data?.notifications?.items;
    if (Array.isArray(items)) {
      return items as NotificationItem[];
    }

    return [];
  }

  private async executeCommand(vin: string, command: string, pin: string): Promise<string> {
    if (!pin) {
      throw new Error('A 4-digit PIN is required to send remote commands');
    }

    await this.ensureAuthenticated();

    const pinAuth = await this.pinAuthenticate(pin);

    const response = await this.signedRequest<CommandResponse>({
      base: 'api',
      method: 'POST',
      path: `/v1/accounts/${this.uid}/vehicles/${vin}/remote`,
      body: {
        command,
        pinAuth,
      },
    });

    const data = response.data;
    if (data?.responseStatus !== 'pending' || !data?.correlationId) {
      const error = data?.debugMsg || 'Unknown error';
      throw new Error(`Command failed to queue: ${error}`);
    }

    return data.correlationId as string;
  }

  private async fetchCommandStatus(vin: string, correlationId: string): Promise<RequestStatus | null> {
    const notifications = await this.getVehicleNotifications(vin);

    for (const item of notifications) {
      if (item?.correlationId !== correlationId) {
        continue;
      }
      const rawStatus = item?.notification?.data?.status;
      if (typeof rawStatus !== 'string') {
        continue;
      }
      const upper = rawStatus.toUpperCase();
      if (upper === 'SUCCESS') {
        return 'SUCCESS';
      }
      if (upper === 'FAILURE' || upper === 'FAILED' || upper === 'ERROR') {
        return 'FAILURE';
      }
      if (upper === 'PENDING' || upper === 'PROCESSING' || upper === 'IN_PROGRESS' || upper === 'STARTED') {
        return 'INITIATED';
      }
      return 'UNKNOWN';
    }

    return null;
  }

  private async signedRequest<T>(config: SignedRequestConfig): Promise<AxiosResponse<T>> {
    if (!this.credentials || !this.brandConfig) {
      throw new Error('No active credentials');
    }

    const baseUrl = config.base === 'api' ? this.brandConfig.api.url : this.brandConfig.auth.url;
    const apiKey = config.base === 'api' ? this.brandConfig.api.key : this.brandConfig.auth.token;

    const url = new URL(config.path.startsWith('/') ? config.path : `/${config.path}`, `${baseUrl.replace(/\/$/, '')}/`);

    if (config.query) {
      for (const [key, value] of Object.entries(config.query)) {
        if (value === undefined || value === null) {
          continue;
        }
        url.searchParams.append(key, String(value));
      }
    }

    let body: string | undefined;
    if (config.body !== undefined) {
      body = typeof config.body === 'string' ? config.body : JSON.stringify(config.body);
    }

    const headers = {
      ...this.defaultAwsHeaders(apiKey),
      ...(config.headers ?? {}),
    };

    if (!hasHeader(headers, 'content-type')) {
      headers['content-type'] = 'application/json';
    }

    const request: aws4.Request = {
      host: url.host,
      method: (config.method || 'GET').toUpperCase(),
      path: url.pathname + url.search,
      service: 'execute-api',
      region: this.brandConfig.region,
      headers: { ...headers },
    };

    if (body) {
      request.body = body;
    }

    aws4.sign(request, {
      accessKeyId: this.credentials.accessKeyId,
      secretAccessKey: this.credentials.secretAccessKey,
      sessionToken: this.credentials.sessionToken,
    });

    const axiosConfig = {
      method: config.method,
      url: url.toString(),
      headers: request.headers as Record<string, string>,
      data: body,
    };

    if (!body) {
      delete axiosConfig.data;
    }

    try {
      return await this.axiosInstance.request<T>(axiosConfig);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const status = error.response?.status;
        const statusText = error.response?.statusText;
        let details = '';
        if (error.response?.data) {
          if (typeof error.response.data === 'string') {
            details = error.response.data;
          } else {
            try {
              details = JSON.stringify(error.response.data);
            } catch {
              details = String(error.response.data);
            }
          }
        }
        const messageParts = [`HTTP ${status ?? '???'}`];
        if (statusText) {
          messageParts.push(statusText);
        }
        if (details) {
          messageParts.push(details);
        }
        throw new Error(messageParts.join(' - '));
      }
      throw error;
    }
  }

  private defaultAwsHeaders(apiKey: string): Record<string, string> {
    if (!this.brandConfig) {
      throw new Error('Brand configuration missing');
    }

    return {
      'x-clientapp-name': 'CWP',
      'x-clientapp-version': '1.0',
      'clientrequestid': generateClientRequestId(),
      'x-api-key': apiKey,
      locale: this.brandConfig.locale,
      'x-originator-type': 'web',
      accept: 'application/json, text/plain, */*',
      'accept-language': this.brandConfig.locale.replace('_', '-'),
      'user-agent': 'python-requests/2.31.0',
    };
  }

  private async pinAuthenticate(pin: string): Promise<string> {
    await this.ensureAuthenticated();

    const payload = {
      pin: Buffer.from(pin).toString('base64'),
    };

    const response = await this.signedRequest<PinAuthResponse>({
      base: 'auth',
      method: 'POST',
      path: `/v1/accounts/${this.uid}/ignite/pin/authenticate`,
      body: payload,
    });

    const token = response.data?.token;
    if (!token) {
      throw new Error('PIN authentication failed');
    }

    return token;
  }

  private isSessionValid(username: string, password: string, brandKey: BrandKey, region: VehicleRegion): boolean {
    if (!this.credentials || !this.username || !this.password || !this.brandKey || !this.region) {
      return false;
    }

    if (this.username !== username || this.password !== password || this.brandKey !== brandKey || this.region !== region) {
      return false;
    }

    const expiresAt = this.credentials.expiration.getTime();
    const now = Date.now();
    const margin = 5 * 60 * 1000;
    return expiresAt - margin > now;
  }

  private async performLogin(): Promise<void> {
    if (!this.username || !this.password || !this.brandConfig) {
      throw new Error('Missing login context');
    }

    const bootstrap = await this.axiosInstance.get(this.brandConfig.loginUrl + '/accounts.webSdkBootstrap', {
      params: { apiKey: this.brandConfig.loginApiKey },
    });

    if (bootstrap.data?.statusCode !== 200) {
      throw new Error('Bootstrap handshake failed');
    }

    const login = await this.axiosInstance.post(this.brandConfig.loginUrl + '/accounts.login', undefined, {
      params: this.withDefaultParams({
        loginID: this.username,
        password: this.password,
        sessionExpiration: 300,
        include: 'profile,data,emails,subscriptions,preferences',
      }),
    });

    if (login.data?.statusCode !== 200 || !login.data?.UID || !login.data?.sessionInfo?.login_token) {
      throw new Error('Account login failed');
    }

    this.uid = login.data.UID;
    const loginToken: string = login.data.sessionInfo.login_token;

    const jwt = await this.axiosInstance.post(this.brandConfig.loginUrl + '/accounts.getJWT', undefined, {
      params: this.withDefaultParams({
        login_token: loginToken,
        fields: 'profile.firstName,profile.lastName,profile.email,country,locale,data.disclaimerCodeGSDP',
      }),
    });

    if (jwt.data?.statusCode !== 200 || !jwt.data?.id_token) {
      throw new Error('Unable to obtain JWT token');
    }

    const tokenResponse = await this.axiosInstance.post(this.brandConfig.tokenUrl, { gigya_token: jwt.data.id_token }, {
      headers: {
        ...this.defaultAwsHeaders(this.brandConfig.api.key),
        'content-type': 'application/json',
      },
    });

    const identityToken = tokenResponse.data?.Token;
    const identityId = tokenResponse.data?.IdentityId;

    if (!identityToken || !identityId) {
      throw new Error('Unable to obtain identity token');
    }

    if (!this.cognitoClient) {
      this.cognitoClient = new CognitoIdentityClient({ region: this.brandConfig.region });
    }

    const credentialsResponse = await this.cognitoClient.send(new GetCredentialsForIdentityCommand({
      IdentityId: identityId,
      Logins: {
        'cognito-identity.amazonaws.com': identityToken,
      },
    }));

    const creds = credentialsResponse.Credentials;
    if (!creds?.AccessKeyId || !creds.SecretKey || !creds.SessionToken) {
      throw new Error('Unable to obtain AWS credentials');
    }

    const expiration = creds.Expiration ? new Date(creds.Expiration) : new Date(Date.now() + 55 * 60 * 1000);

    this.credentials = {
      accessKeyId: creds.AccessKeyId,
      secretAccessKey: creds.SecretKey,
      sessionToken: creds.SessionToken,
      expiration,
    };
  }

  private withDefaultParams(params: Record<string, unknown>): Record<string, unknown> {
    if (!this.brandConfig) {
      throw new Error('Brand configuration missing');
    }

    return {
      targetEnv: 'jssdk',
      loginMode: 'standard',
      sdk: 'js_latest',
      authMode: 'cookie',
      sdkBuild: '12234',
      format: 'json',
      APIKey: this.brandConfig.loginApiKey,
      ...params,
    };
  }

  private createHttpClient(): { client: AxiosInstance; jar: CookieJar } {
    const jar = new CookieJar();
    const client = wrapper(axios.create({
      jar,
      withCredentials: true,
      timeout: 30000,
      validateStatus: status => (status ?? 0) >= 200 && (status ?? 0) < 400,
    }));
    return { client, jar };
  }
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  const lower = name.toLowerCase();
  return Object.keys(headers).some(header => header.toLowerCase() === lower);
}

function generateClientRequestId(): string {
  return randomUUID().replace(/-/g, '').toUpperCase().slice(0, 16);
}

function sanitizeString(value: unknown): string {
  if (typeof value === 'string') {
    return value.trim();
  }
  if (typeof value === 'number') {
    return String(value);
  }
  return '';
}

function resolveBrandKey(brand: VehicleBrand, region: VehicleRegion): BrandKey {
  const regionMap = BRAND_REGION_MAP[brand];
  const priority: VehicleRegion[] = [region, 'us', 'eu', 'ca', 'asia'];
  for (const candidate of priority) {
    const key = regionMap[candidate];
    if (key) {
      return key;
    }
  }
  throw new Error(`Unsupported brand/region combination: ${brand}/${region}`);
}

function mapBrandKeyToVehicleBrand(key: BrandKey): VehicleBrand {
  for (const [brand, regionMap] of Object.entries(BRAND_REGION_MAP) as Array<[VehicleBrand, Partial<Record<VehicleRegion, BrandKey>>]>) {
    if (Object.values(regionMap).includes(key)) {
      return brand;
    }
  }
  throw new Error(`Unable to map brand key ${key}`);
}

const apiInstance = new MoparApi();

async function signInWithRetry(
  username: string,
  password: string,
  brand: VehicleBrand,
  region: VehicleRegion,
  maxRetries = 3,
): Promise<boolean> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await apiInstance.signIn(username, password, brand, region);
      return true;
    } catch (error) {
      if (attempt === maxRetries) {
        throw error;
      }
      await delay(2000);
    }
  }
  return false;
}

function isValidRequestId(requestId: string): boolean {
  const pat = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
  return pat.test(requestId);
}

async function lockCar(vin: string, pin: string, _useGuardian?: boolean): Promise<string> {
  void _useGuardian;
  return apiInstance.lockCar(vin, pin);
}

async function unlockCar(vin: string, pin: string, _useGuardian?: boolean): Promise<string> {
  void _useGuardian;
  return apiInstance.unlockCar(vin, pin);
}

async function startCar(vin: string, pin: string, _useGuardian?: boolean): Promise<string> {
  void _useGuardian;
  return apiInstance.startCar(vin, pin);
}

async function stopCar(vin: string, pin: string, _useGuardian?: boolean): Promise<string> {
  void _useGuardian;
  return apiInstance.stopCar(vin, pin);
}

async function checkLockStatus(vin: string, requestId: string, timeout: number, _useGuardian?: boolean): Promise<RequestStatus> {
  void _useGuardian;
  return apiInstance.checkCommandStatus(vin, requestId, timeout);
}

async function checkUnlockStatus(vin: string, requestId: string, timeout: number, _useGuardian?: boolean): Promise<RequestStatus> {
  void _useGuardian;
  return apiInstance.checkCommandStatus(vin, requestId, timeout);
}

async function checkStartStatus(vin: string, requestId: string, timeout: number, _useGuardian?: boolean): Promise<RequestStatus> {
  void _useGuardian;
  return apiInstance.checkCommandStatus(vin, requestId, timeout);
}

async function checkStopStatus(vin: string, requestId: string, timeout: number, _useGuardian?: boolean): Promise<RequestStatus> {
  void _useGuardian;
  return apiInstance.checkCommandStatus(vin, requestId, timeout);
}

async function getVehicleData(): Promise<VehicleInfo[] | string> {
  try {
    return await apiInstance.getVehicles();
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    }
    if (error instanceof Error) {
      return error.message;
    }
    return 'An unexpected error occurred';
  }
}

export const moparApi = {
  signIn: signInWithRetry,
  getVehicleData,
  lockCar,
  unlockCar,
  startCar,
  stopCar,
  checkLockStatus,
  checkUnlockStatus,
  checkStartStatus,
  checkStopStatus,
  isValidRequestId,
};
