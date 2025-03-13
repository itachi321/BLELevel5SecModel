#include <stdint.h>

// Reference: https://en.cppreference.com/w/cpp/feature_test
#if __cplusplus >= 200704L
constexpr
#endif
const uint8_t profile_data_central[] =
{
    // ATT DB Version
    1,

    // 0x0001 PRIMARY_SERVICE-GAP_SERVICE
    0x0a, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x28, 0x00, 0x18, 
    // 0x0002 CHARACTERISTIC-GAP_DEVICE_NAME - READ
    0x0d, 0x00, 0x02, 0x00, 0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x00, 0x2a, 
    // 0x0003 VALUE CHARACTERISTIC-GAP_DEVICE_NAME - READ -'SM Pairing Central'
    // READ_ANYBODY
    0x1a, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x2a, 0x53, 0x4d, 0x20, 0x50, 0x61, 0x69, 0x72, 0x69, 0x6e, 0x67, 0x20, 0x43, 0x65, 0x6e, 0x74, 0x72, 0x61, 0x6c, 
    // 0x0004 PRIMARY_SERVICE-GATT_SERVICE
    0x0a, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x28, 0x01, 0x18, 
    // 0x0005 CHARACTERISTIC-GATT_DATABASE_HASH - READ
    0x0d, 0x00, 0x02, 0x00, 0x05, 0x00, 0x03, 0x28, 0x02, 0x06, 0x00, 0x2a, 0x2b, 
    // 0x0006 VALUE CHARACTERISTIC-GATT_DATABASE_HASH - READ -''
    // READ_ANYBODY
    0x18, 0x00, 0x02, 0x00, 0x06, 0x00, 0x2a, 0x2b, 0x78, 0x72, 0xbd, 0x03, 0x5e, 0x7e, 0x06, 0x0f, 0x34, 0xf6, 0x04, 0xcc, 0x58, 0x7c, 0x8f, 0xde, 
    // Dummy Service
    // 0x0007 PRIMARY_SERVICE-0000FF10-0000-1000-8000-00805F9B34FB
    0x18, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x28, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x10, 0xff, 0x00, 0x00, 
    // Dummy Service, Characteristic, with read and notify + authentication
    // 0x0008 CHARACTERISTIC-0000FF12-0000-1000-8000-00805F9B34FB - READ | ENCRYPTION_KEY_SIZE_16
    0x1b, 0x00, 0x02, 0x00, 0x08, 0x00, 0x03, 0x28, 0x02, 0x09, 0x00, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x12, 0xff, 0x00, 0x00, 
    // 0x0009 VALUE CHARACTERISTIC-0000FF12-0000-1000-8000-00805F9B34FB - READ | ENCRYPTION_KEY_SIZE_16 -'Secure :)'
    // READ_ENCRYPTED, ENCRYPTION_KEY_SIZE=16
    0x1f, 0x00, 0x03, 0xf6, 0x09, 0x00, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x12, 0xff, 0x00, 0x00, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x3a, 0x29, 
    // END
    0x00, 0x00, 
}; // total size 99 bytes 

const uint8_t profile_data_peripheral[] =
{
    // ATT DB Version
    1,

    // 0x0001 PRIMARY_SERVICE-GAP_SERVICE
    0x0a, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x28, 0x00, 0x18, 
    // 0x0002 CHARACTERISTIC-GAP_DEVICE_NAME - READ
    0x0d, 0x00, 0x02, 0x00, 0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x00, 0x2a, 
    // 0x0003 VALUE CHARACTERISTIC-GAP_DEVICE_NAME - READ -'SM Pairing Peripheral'
    // READ_ANYBODY
    0x1d, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x2a, 0x53, 0x4d, 0x20, 0x50, 0x61, 0x69, 0x72, 0x69, 0x6e, 0x67, 0x20, 0x50, 0x65, 0x72, 0x69, 0x70, 0x68, 0x65, 0x72, 0x61, 0x6c, 
    // 0x0004 PRIMARY_SERVICE-GATT_SERVICE
    0x0a, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x28, 0x01, 0x18, 
    // 0x0005 CHARACTERISTIC-GATT_DATABASE_HASH - READ
    0x0d, 0x00, 0x02, 0x00, 0x05, 0x00, 0x03, 0x28, 0x02, 0x06, 0x00, 0x2a, 0x2b, 
    // 0x0006 VALUE CHARACTERISTIC-GATT_DATABASE_HASH - READ -''
    // READ_ANYBODY
    0x18, 0x00, 0x02, 0x00, 0x06, 0x00, 0x2a, 0x2b, 0xbd, 0x35, 0xfe, 0x86, 0x39, 0x43, 0x72, 0x7f, 0x6a, 0x24, 0xc0, 0xd4, 0x3a, 0x39, 0xe6, 0x5f, 
    // Dummy Service
    // 0x0007 PRIMARY_SERVICE-0000FF10-0000-1000-8000-00805F9B34FB
    0x18, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x28, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x10, 0xff, 0x00, 0x00, 
    // Dummy Service, Characteristic, with read and notify + authentication
    // 0x0008 CHARACTERISTIC-0000FF12-0000-1000-8000-00805F9B34FB - READ | ENCRYPTION_KEY_SIZE_16
    0x1b, 0x00, 0x02, 0x00, 0x08, 0x00, 0x03, 0x28, 0x02, 0x09, 0x00, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x12, 0xff, 0x00, 0x00, 
    // 0x0009 VALUE CHARACTERISTIC-0000FF12-0000-1000-8000-00805F9B34FB - READ | ENCRYPTION_KEY_SIZE_16 -'Secure :)'
    // READ_ENCRYPTED, ENCRYPTION_KEY_SIZE=16
    0x1f, 0x00, 0x03, 0xf6, 0x09, 0x00, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x12, 0xff, 0x00, 0x00, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x3a, 0x29, 
    // END
    0x00, 0x00, 
}; // total size 99 bytes 

//
// list service handle ranges
//
#define ATT_SERVICE_GAP_SERVICE_START_HANDLE 0x0001
#define ATT_SERVICE_GAP_SERVICE_END_HANDLE 0x0003
#define ATT_SERVICE_GAP_SERVICE_01_START_HANDLE 0x0001
#define ATT_SERVICE_GAP_SERVICE_01_END_HANDLE 0x0003
#define ATT_SERVICE_GATT_SERVICE_START_HANDLE 0x0004
#define ATT_SERVICE_GATT_SERVICE_END_HANDLE 0x0006
#define ATT_SERVICE_GATT_SERVICE_01_START_HANDLE 0x0004
#define ATT_SERVICE_GATT_SERVICE_01_END_HANDLE 0x0006
#define ATT_SERVICE_0000FF10_0000_1000_8000_00805F9B34FB_START_HANDLE 0x0007
#define ATT_SERVICE_0000FF10_0000_1000_8000_00805F9B34FB_END_HANDLE 0x0009
#define ATT_SERVICE_0000FF10_0000_1000_8000_00805F9B34FB_01_START_HANDLE 0x0007
#define ATT_SERVICE_0000FF10_0000_1000_8000_00805F9B34FB_01_END_HANDLE 0x0009

//
// list mapping between characteristics and handles
//
#define ATT_CHARACTERISTIC_GAP_DEVICE_NAME_01_VALUE_HANDLE 0x0003
#define ATT_CHARACTERISTIC_GATT_DATABASE_HASH_01_VALUE_HANDLE 0x0006
#define ATT_CHARACTERISTIC_0000FF12_0000_1000_8000_00805F9B34FB_01_VALUE_HANDLE 0x0009
