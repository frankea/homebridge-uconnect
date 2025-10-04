import axios from 'axios';
import qs from 'qs';
import { VehicleBrand, VEHICLE_BRANDS } from './settings';

function setAxiosDefaults() : void {
  axios.defaults.headers.common['content-type'] = 'application/x-www-form-urlencoded';
  axios.defaults.maxRedirects = 0;
  axios.defaults.validateStatus = function (status) {
    return status >= 200 && status <= 302;
  };
}

function createCookie(cookies: object) : string {
  return Object.entries(cookies).reduce((pv, cv) => pv + cv[0] + '=' + cv[1] + ';', '');
}

function updateCookies(newCookies: Array<string> | undefined) : void {
  const cookies = Object.assign(parseCookies(String(axios.defaults.headers.common['Cookie'])), parseCookies(newCookies));
  axios.defaults.headers.common['Cookie'] = createCookie(cookies);
}

function parseCookies(cookies: string | Array<string> | undefined) : object {
  const cookieObj = {};
  const pat = /(?<key>\w+)=(?<value>[^;]+);?/;
  if (typeof(cookies) === 'string') {
    cookies = cookies.split(';');
  }
  for (const cookie of cookies || []) {
    const r = cookie.match(pat);
    if (r?.groups) {
      cookieObj[r.groups.key] = r.groups.value;
    }
  }
  return cookieObj;
}

interface AuthConfig {
  target: string;
  loginUrl: string;
  samlUrl: string;
  samlData: object;
  relayState: string;
  samlPostEndpoint: string;
  loadingPath: string;
  signInPath: string;
  dashboardPath: string;
  apiBaseUrl: string;
}

function getAuthConfig(brand: VehicleBrand): AuthConfig {
  const baseUrl = VEHICLE_BRANDS[brand].connectUrl;

  // Brand-specific authentication configurations based on Home Assistant integration patterns
  switch (brand) {
    case 'jeep':
      return {
        target: 'https://sso.extra.chrysler.com/cgi-bin/moparproderedirect.cgi?env=prd&PartnerSpId=B2CAEM&IdpAdapterId=B2CSM&appID=MOPUSEN_C&TargetResource=' +
                baseUrl + '/sign-in',
        loginUrl: 'https://sso.extra.chrysler.com/siteminderagent/forms/b2clogin.fcc',
        samlUrl: 'https://federation.chrysler.com/idp/startSSO.ping?',
        samlData: {
          'PartnerSpId': 'B2CAEM',
          'IdpAdapterId': 'B2CSM',
          'ACSIdx': '',
          'TargetResource': baseUrl + '/sign-in',
        },
        relayState: baseUrl + '/sign-in',
        samlPostEndpoint: 'sign-in',
        loadingPath: 'en-us/loading.html',
        signInPath: 'sign-in',
        dashboardPath: 'jeep/en-us/my-vehicle/dashboard.html',
        apiBaseUrl: baseUrl + '/jeepsvc',
      };

    case 'fiat':
      return {
        target: 'https://sso.extra.chrysler.com/cgi-bin/moparproderedirect.cgi?env=prd&PartnerSpId=B2CAEM&IdpAdapterId=B2CSM&appID=MOPUSEN_C&TargetResource=' +
                baseUrl + '/sign-in',
        loginUrl: 'https://sso.extra.chrysler.com/siteminderagent/forms/b2clogin.fcc',
        samlUrl: 'https://federation.chrysler.com/idp/startSSO.ping?',
        samlData: {
          'PartnerSpId': 'B2CAEM',
          'IdpAdapterId': 'B2CSM',
          'ACSIdx': '',
          'TargetResource': baseUrl + '/sign-in',
        },
        relayState: baseUrl + '/sign-in',
        samlPostEndpoint: 'sign-in',
        loadingPath: 'en-us/loading.html',
        signInPath: 'sign-in',
        dashboardPath: 'fiat/en-us/my-vehicle/dashboard.html',
        apiBaseUrl: baseUrl + '/fiatsvc',
      };

    case 'ram':
      return {
        target: 'https://sso.extra.chrysler.com/cgi-bin/moparproderedirect.cgi?env=prd&PartnerSpId=B2CAEM&IdpAdapterId=B2CSM&appID=MOPUSEN_C&TargetResource=' +
                baseUrl + '/sign-in',
        loginUrl: 'https://sso.extra.chrysler.com/siteminderagent/forms/b2clogin.fcc',
        samlUrl: 'https://federation.chrysler.com/idp/startSSO.ping?',
        samlData: {
          'PartnerSpId': 'B2CAEM',
          'IdpAdapterId': 'B2CSM',
          'ACSIdx': '',
          'TargetResource': baseUrl + '/sign-in',
        },
        relayState: baseUrl + '/sign-in',
        samlPostEndpoint: 'sign-in',
        loadingPath: 'en-us/loading.html',
        signInPath: 'sign-in',
        dashboardPath: 'ram/en-us/my-vehicle/dashboard.html',
        apiBaseUrl: baseUrl + '/ramsvc',
      };

    case 'dodge':
      return {
        target: 'https://sso.extra.chrysler.com/cgi-bin/moparproderedirect.cgi?env=prd&PartnerSpId=B2CAEM&IdpAdapterId=B2CSM&appID=MOPUSEN_C&TargetResource=' +
                baseUrl + '/sign-in',
        loginUrl: 'https://sso.extra.chrysler.com/siteminderagent/forms/b2clogin.fcc',
        samlUrl: 'https://federation.chrysler.com/idp/startSSO.ping?',
        samlData: {
          'PartnerSpId': 'B2CAEM',
          'IdpAdapterId': 'B2CSM',
          'ACSIdx': '',
          'TargetResource': baseUrl + '/sign-in',
        },
        relayState: baseUrl + '/sign-in',
        samlPostEndpoint: 'sign-in',
        loadingPath: 'en-us/loading.html',
        signInPath: 'sign-in',
        dashboardPath: 'dodge/en-us/my-vehicle/dashboard.html',
        apiBaseUrl: baseUrl + '/dodgesvc',
      };

    case 'alfa_romeo':
      return {
        target: 'https://sso.extra.chrysler.com/cgi-bin/moparproderedirect.cgi?env=prd&PartnerSpId=B2CAEM&IdpAdapterId=B2CSM&appID=MOPUSEN_C&TargetResource=' +
                baseUrl + '/sign-in',
        loginUrl: 'https://sso.extra.chrysler.com/siteminderagent/forms/b2clogin.fcc',
        samlUrl: 'https://federation.chrysler.com/idp/startSSO.ping?',
        samlData: {
          'PartnerSpId': 'B2CAEM',
          'IdpAdapterId': 'B2CSM',
          'ACSIdx': '',
          'TargetResource': baseUrl + '/sign-in',
        },
        relayState: baseUrl + '/sign-in',
        samlPostEndpoint: 'sign-in',
        loadingPath: 'en-us/loading.html',
        signInPath: 'sign-in',
        dashboardPath: 'alfa-romeo/en-us/my-vehicle/dashboard.html',
        apiBaseUrl: baseUrl + '/alfaromeosvc',
      };

    case 'chrysler':
      return {
        target: 'https://sso.extra.chrysler.com/cgi-bin/moparproderedirect.cgi?env=prd&PartnerSpId=B2CAEM&IdpAdapterId=B2CSM&appID=MOPUSEN_C&TargetResource=' +
                baseUrl + '/sign-in',
        loginUrl: 'https://sso.extra.chrysler.com/siteminderagent/forms/b2clogin.fcc',
        samlUrl: 'https://federation.chrysler.com/idp/startSSO.ping?',
        samlData: {
          'PartnerSpId': 'B2CAEM',
          'IdpAdapterId': 'B2CSM',
          'ACSIdx': '',
          'TargetResource': baseUrl + '/sign-in',
        },
        relayState: baseUrl + '/sign-in',
        samlPostEndpoint: 'sign-in',
        loadingPath: 'en-us/loading.html',
        signInPath: 'sign-in',
        dashboardPath: 'chrysler/en-us/my-vehicle/dashboard.html',
        apiBaseUrl: baseUrl + '/chryslersvc',
      };

    case 'maserati':
      return {
        target: 'https://sso.extra.chrysler.com/cgi-bin/moparproderedirect.cgi?env=prd&PartnerSpId=B2CAEM&IdpAdapterId=B2CSM&appID=MOPUSEN_C&TargetResource=' +
                baseUrl + '/sign-in',
        loginUrl: 'https://sso.extra.chrysler.com/siteminderagent/forms/b2clogin.fcc',
        samlUrl: 'https://federation.chrysler.com/idp/startSSO.ping?',
        samlData: {
          'PartnerSpId': 'B2CAEM',
          'IdpAdapterId': 'B2CSM',
          'ACSIdx': '',
          'TargetResource': baseUrl + '/sign-in',
        },
        relayState: baseUrl + '/sign-in',
        samlPostEndpoint: 'sign-in',
        loadingPath: 'en-us/loading.html',
        signInPath: 'sign-in',
        dashboardPath: 'maserati/en-us/my-vehicle/dashboard.html',
        apiBaseUrl: baseUrl + '/maseratisvc',
      };

    default:
      throw new Error(`Unsupported brand: ${brand}`);
  }
}

async function signInWithRetry(username: string, password: string, brand: VehicleBrand, maxRetries = 3): Promise<boolean> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const success = await signIn(username, password, brand);
      return success;
    } catch (error) {
      if (attempt === maxRetries) {
        throw error; // Re-throw the last error
      }
      // Wait before retry
      await delay(2000);
    }
  }
  return false;
}

async function signIn(username: string, password: string, brand: VehicleBrand): Promise<boolean> {
  try {
    // Use brand-specific base URL
    const baseUrl = VEHICLE_BRANDS[brand].connectUrl;
    axios.defaults.baseURL = baseUrl;

    // Brand-specific authentication flow
    const authConfig = getAuthConfig(brand);

    const data1 = {
      'USER': username,
      'PASSWORD': password,
      'TARGET': authConfig.target,
    };

    const res1 = await axios.post(authConfig.loginUrl, qs.stringify(data1));

    const data2 = authConfig.samlData;
    const url2 = authConfig.samlUrl + qs.stringify(data2);
    const cookies = parseCookies(res1.headers['set-cookie']);
    const res2 = await axios.get(url2, {headers: {Cookie: createCookie(cookies)}});

    const pat = /name="SAMLResponse" value="([^"]+)"/;
    const samlMatch = res2.data.match(pat);
    if (!samlMatch) {
      throw new Error(`Failed to extract SAML response from ${brand} authentication page`);
    }
    const saml = samlMatch[1];

    const data3 = {
      'RelayState': authConfig.relayState,
      'SAMLResponse': saml,
    };
    const res3 = await axios.post(authConfig.samlPostEndpoint, qs.stringify(data3));
    updateCookies(res3.headers['set-cookie']);

    // Brand-specific loading/dashboard flow
    const loadingResponse = await axios.get(authConfig.loadingPath);
    updateCookies(loadingResponse.headers['set-cookie']);

    const signInResponse = await axios.get(authConfig.signInPath);
    updateCookies(signInResponse.headers['set-cookie']);

    const dashboardResponse = await axios.get(authConfig.dashboardPath);
    updateCookies(dashboardResponse.headers['set-cookie']);

    // Set API base URL for subsequent API calls
    axios.defaults.baseURL = authConfig.apiBaseUrl;

    return true;
  } catch (error) {
    // Detailed error logging for debugging authentication issues
    let errorMessage = 'Authentication failed with error: ';
    if (axios.isAxiosError(error)) {
      errorMessage += `Axios error: ${error.message}`;
      if (error.response?.status) {
        errorMessage += `, Status: ${error.response.status}`;
      }
      if (error.response?.statusText) {
        errorMessage += `, StatusText: ${error.response.statusText}`;
      }

      // Check for specific error patterns
      if (error.response?.status === 302) {
        errorMessage += ' (Got 302 redirect - this might indicate authentication failure)';
      }
      if (error.response?.data && typeof error.response.data === 'string') {
        if (error.response.data.includes('invalid') || error.response.data.includes('error')) {
          errorMessage += ' (Server returned authentication error in response body)';
        }
      }
    } else {
      errorMessage += `Non-axios error: ${error}`;
    }

    // For now, we'll throw the error so it can be caught and logged by the calling code
    throw new Error(errorMessage);
  }
}

async function signOut() : Promise<string> {
  try {
    axios.defaults.baseURL = 'https://www.mopar.com';
    await axios.post('sign-out');
    return '';
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  }
}

async function getUserData() : Promise<object | string> {
  try {
    const { data, headers } = await axios.get('user/getProfile');
    updateCookies(headers['set-cookie']);

    return data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  }
}

interface VehicleInfo {
  vin: string;
  title: string;
  make: string;
  model: string;
  year: string;
  // Guardian-specific fields that may be present
  subscriptionType?: string;
  services?: string[];
  capabilities?: string[];
}

async function getVehicleData() : Promise<Array<VehicleInfo> | string> {
  try {
    const { data, headers } = await axios.get('user/getVehicles');
    updateCookies(headers['set-cookie']);

    return data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  }
}

function isGuardianVehicle(vehicle: VehicleInfo): boolean {
  // Check for Guardian indicators in vehicle data
  if (vehicle.subscriptionType?.toLowerCase().includes('guardian') ||
      vehicle.subscriptionType?.toLowerCase().includes('siriusxm')) {
    return true;
  }

  // Check services array for Guardian services
  if (vehicle.services?.some(service =>
    service.toLowerCase().includes('guardian') ||
    service.toLowerCase().includes('siriusxm')
  )) {
    return true;
  }

  // Check capabilities for Guardian features
  if (vehicle.capabilities?.some(capability =>
    capability.toLowerCase().includes('guardian') ||
    capability.toLowerCase().includes('theft') ||
    capability.toLowerCase().includes('emergency')
  )) {
    return true;
  }

  return false;
}

// Guardian-specific API endpoints
interface GuardianEndpoints {
  lock: string;
  unlock: string;
  engineStart: string;
  engineStop: string;
  status: string;
}

function getGuardianEndpoints(brand: VehicleBrand): GuardianEndpoints {
  const baseUrl = VEHICLE_BRANDS[brand].connectUrl;

  // These are speculative endpoints based on typical Guardian API patterns
  // In practice, these would need to be reverse-engineered from the Guardian app/API
  return {
    lock: `${baseUrl}/guardian/lock`,
    unlock: `${baseUrl}/guardian/unlock`,
    engineStart: `${baseUrl}/guardian/engine/start`,
    engineStop: `${baseUrl}/guardian/engine/stop`,
    status: `${baseUrl}/guardian/status`,
  };
}

async function getVehicleHealthReport(vin: string) : Promise<object | string> {
  try {
    const url = 'getVHR?' + qs.stringify({vin: vin});
    const { data, headers } = await axios.get(url);
    updateCookies(headers['set-cookie']);

    return data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  }
}

async function getToken() : Promise<string> {
  try {
    const { data } = await axios.get('token');

    return data.token;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  }
}

export type RequestStatus = 'INITIATED' | 'SUCCESS' | 'FAILURE';
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

// Lock Mechanism
export type LockAction = 'LOCK' | 'UNLOCK';

async function lockCarFunc(vin: string, pin: string, action: LockAction, useGuardian = false) : Promise<string> {
  try {
    const reqData = {
      'action': action,
      'vin': vin,
      'pin': pin,
    };
    const token = await getToken();

    let endpoint = 'connect/lock';
    let requestHeaders: {headers: {'MOPAR-CSRF-SALT': string; 'Content-Type'?: string}} = {headers: {'MOPAR-CSRF-SALT': token}};

    // Try Guardian endpoints if specified or if standard fails
    if (useGuardian) {
      // For Guardian vehicles, use different endpoint structure
      // This is speculative - actual Guardian API would need reverse engineering
      endpoint = 'guardian/remote/lock';
      requestHeaders = {
        headers: {
          'MOPAR-CSRF-SALT': token,
          'Content-Type': 'application/json'
        }
      };
      // Guardian might use different request format
      reqData['command'] = action.toLowerCase();
    }

    const { data, headers } = await axios.post(endpoint, useGuardian ? JSON.stringify(reqData) : qs.stringify(reqData), requestHeaders);
    updateCookies(headers['set-cookie']);

    // Handle different response formats for Guardian vs Standard
    if (useGuardian && data.requestId) {
      return data.requestId;
    }

    return data.serviceRequestId;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  }
}

function lockCar(vin: string, pin: string, useGuardian = false) : Promise<string> {
  return lockCarFunc(vin, pin, 'LOCK', useGuardian);
}

function unlockCar(vin: string, pin: string, useGuardian = false) : Promise<string> {
  return lockCarFunc(vin, pin, 'UNLOCK', useGuardian);
}

async function requestLockStatus(vin: string, requestId: string, action: LockAction, useGuardian = false) : Promise<string> {
  try {
    const reqData = {
      'action': action,
      'vin': vin,
      'remoteServiceRequestID': requestId,
    };

    let url = 'connect/lock?' + qs.stringify(reqData);

    if (useGuardian) {
      // Guardian might use different status checking
      url = 'guardian/remote/status?' + qs.stringify({
        vin: vin,
        requestId: requestId,
        action: action.toLowerCase()
      });
    }

    const { data, headers } = await axios.get(url);
    updateCookies(headers['set-cookie']);

    if (useGuardian && data.status) {
      return data.status;
    }

    return data.status;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  }
}

async function checkLockingStatus(vin: string, requestId: string, action: LockAction, timeout: number, useGuardian = false) : Promise<string> {
  let status = '';
  do {
    timeout--;
    // Wait for 1s
    await delay(1000);
    status = await requestLockStatus(vin, requestId, action, useGuardian);
  } while (status === 'INITIATED' && timeout > 0);
  return status;
}

function checkLockStatus(vin: string, requestId: string, timeout: number, useGuardian = false) : Promise<string> {
  return checkLockingStatus(vin, requestId, 'LOCK', timeout, useGuardian);
}

function checkUnlockStatus(vin: string, requestId: string, timeout: number, useGuardian = false) : Promise<string> {
  return checkLockingStatus(vin, requestId, 'UNLOCK', timeout, useGuardian);
}

// Engine Start Mechanism
export type EngineAction = 'START' | 'STOP';

async function engineFunc(vin: string, pin: string, action: EngineAction, useGuardian = false) : Promise<string> {
  try {
    const reqData = {
      'action': action,
      'vin': vin,
      'pin': pin,
    };
    const token = await getToken();

    let endpoint = 'connect/engine';
    let requestHeaders: {headers: {'MOPAR-CSRF-SALT': string; 'Content-Type'?: string}} = {headers: {'MOPAR-CSRF-SALT': token}};

    if (useGuardian) {
      endpoint = 'guardian/remote/engine';
      requestHeaders = {
        headers: {
          'MOPAR-CSRF-SALT': token,
          'Content-Type': 'application/json'
        }
      };
      reqData['command'] = action.toLowerCase();
    }

    const { data, headers } = await axios.post(endpoint, useGuardian ? JSON.stringify(reqData) : qs.stringify(reqData), requestHeaders);
    updateCookies(headers['set-cookie']);

    if (useGuardian && data.requestId) {
      return data.requestId;
    }

    return data.serviceRequestId;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  }
}

function startCar(vin: string, pin: string, useGuardian = false) : Promise<string> {
  return engineFunc(vin, pin, 'START', useGuardian);
}

function stopCar(vin: string, pin: string, useGuardian = false) : Promise<string> {
  return engineFunc(vin, pin, 'STOP', useGuardian);
}

async function requestEngineStatus(vin: string, requestId: string, action: EngineAction, useGuardian = false) : Promise<string> {
  try {
    const reqData = {
      'action': action,
      'vin': vin,
      'remoteServiceRequestID': requestId,
    };

    let url = 'connect/engine?' + qs.stringify(reqData);

    if (useGuardian) {
      url = 'guardian/remote/status?' + qs.stringify({
        vin: vin,
        requestId: requestId,
        action: action.toLowerCase()
      });
    }

    const { data, headers } = await axios.get(url);
    updateCookies(headers['set-cookie']);

    if (useGuardian && data.status) {
      return data.status;
    }

    return data.status;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return error.message;
    } else {
      return 'An unexpected error occurred';
    }
  }
}

async function checkEngineStatus(vin: string, requestId: string, action: EngineAction, timeout: number, useGuardian = false) : Promise<string> {
  let status = '';
  do {
    timeout--;
    // Wait for 1s
    await delay(1000);
    status = await requestEngineStatus(vin, requestId, action, useGuardian);
  } while (status === 'INITIATED' && timeout > 0);
  return status;
}

function checkStartStatus(vin: string, requestId: string, timeout: number, useGuardian = false) : Promise<string> {
  return checkEngineStatus(vin, requestId, 'START', timeout, useGuardian);
}

function checkStopStatus(vin: string, requestId: string, timeout: number, useGuardian = false) : Promise<string> {
  return checkEngineStatus(vin, requestId, 'STOP', timeout, useGuardian);
}

function isValidRequestId(requestId: string) : boolean {
  const hex = '[a-fA-F0-9]';
  const pat = new RegExp(`${hex}{8}-${hex}{4}-${hex}{4}-${hex}{4}-${hex}{12}`);
  return pat.test(requestId);
}

setAxiosDefaults();
export const moparApi = {
  signIn: signInWithRetry, // Now requires brand parameter
  signOut: signOut,
  getUserData: getUserData,
  getVehicleData: getVehicleData,
  getVehicleHealthReport: getVehicleHealthReport,
  getToken: getToken,
  lockCar: lockCar,
  unlockCar: unlockCar,
  checkLockStatus: checkLockStatus,
  checkUnlockStatus: checkUnlockStatus,
  startCar: startCar,
  stopCar: stopCar,
  checkStartStatus: checkStartStatus,
  checkStopStatus: checkStopStatus,
  isValidRequestId: isValidRequestId,
};