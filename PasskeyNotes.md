# Passkey Notes
Notes and questions on using WebAuthn passkeys.

## The power source
The power of passkeys originates in the TPM (Trusted Platform Module) of the computer/device. The TPM is a cryptographic device that is used in creation of private keys.

A passkey is a public/private keypair where the public key is provided to the web account to be accessed and the private key is stored on the device or in the cloud (iCloud, Google account, ...)

## You MUST have two or more devices
To be able to recover account access after loss of a passkey or device, you have to have already created a passkey for the account from another device. The 2nd device can be a phone, another computer, a Yubikey, et.al.

On Apple, passkeys are stored in iCloud. So, if your Mac crashes, then your iPhone/iPad can be used as access. 
You could also have two different devices ecosystems (ex. Mac and Android phone).

## Moving to different device vendor
Exporting passkeys from one vendor to another is problematic (2023). Best to expect to have to manually create new passkeys for each account in the new vendor.

## Vendors are responsible for creating/syncing passkeys
Chrome on a Mac stores passkeys in the user's Google account.

Apple (safari) stores passkeys in iCloud and other devices logged into the same iCloud account have access to the same passkeys.

## Autofill form
Automatically provide passkey choices to the user, typically from the `username` field of a login form.