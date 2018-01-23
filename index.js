
import { Platform, NativeModules } from 'react-native';

// const { RNRSAKeychain } = NativeModules;
// const { RNRSA } = NativeModules;

// export { RNRSAKeychain, RNRSAKeychain as RSAKeychain, RNRSA, RNRSA as RSA };

// export default RNRSA;

let RSADigitalSignatureModule;
let RSAKeygenModule;

if (Platform.OS === 'ios') {
  RSADigitalSignatureModule = NativeModules.RNSign;
  RSAKeygenModule = NativeModules.RNKeyPair;
} else {
  RSADigitalSignatureModule = NativeModules.RNRSA;
  RSAKeygenModule = NativeModules.RNRSA;
}

export { RSADigitalSignatureModule as RSASign, RSAKeygenModule as RSAKeyPair };
