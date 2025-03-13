#define BTSTACK_FILE__ "le_pairing.c"

#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "btstack.h"
#include "le_pairing.h"

#define REMOTE_SERVICE 0x1111

typedef enum {
    RO_UNKNOWN,
    RO_CENTRAL,
    RO_PERIPHERAL,
} device_role_t;

typedef struct {
    bd_addr_type_t address_type;
    bd_addr_t address;
} device_data_t;

const uint8_t adv_data[] = {
    // Flags general discoverable, BR/EDR not supported
    0x02,
    BLUETOOTH_DATA_TYPE_FLAGS,
    0x06,
    // Name
    0x0b,
    BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME,
    'S',
    'M',
    ' ',
    'P',
    'a',
    'i',
    'r',
    'i',
    'n',
    'g',
    // Incomplete List of 16-bit Service Class UUIDs -- 1111 - only valid for testing!
    0x03,
    BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
    0x11,
    0x11,
};
const uint8_t adv_data_len = sizeof(adv_data);

static bool flag_device_console = false;
static device_role_t role = RO_UNKNOWN;
static io_capability_t io_capability = IO_CAPABILITY_DISPLAY_ONLY;

static bd_addr_t remote_addr = { 0 };

static btstack_packet_callback_registration_t hci_event_callback_registration;
static btstack_packet_callback_registration_t sm_event_callback_registration;

static void central_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size);
static void central_sm_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size);
static void peripheral_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size);
static void peripheral_sm_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size);

static void console_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size);

static inline long long get_microsecond_timestamp(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long microsecond_timestamp = (long long)tv.tv_sec * 1000000 + tv.tv_usec;
    return microsecond_timestamp;
}

static inline void sm_setup(const uint8_t profile_data[])
{
    l2cap_init();
    sm_init();
    att_server_init(profile_data, NULL, NULL);
    gatt_client_init();
}

static inline void sm_config(void)
{
    sm_set_io_capabilities(io_capability);

    uint8_t auth_req = SM_AUTHREQ_BONDING | SM_AUTHREQ_MITM_PROTECTION;
#ifdef ENABLE_LE_PFS
    auth_req |= SM_AUTHREQ_PFS;
    printf("[-] PFS enabled\n");
#endif
#ifdef ENABLE_LE_SECURE_CONNECTIONS
    auth_req |= SM_AUTHREQ_SECURE_CONNECTION;
    printf("[-] Secure Connections enabled\n");
#endif
    sm_set_authentication_requirements(auth_req);
}

static void sm_numeric_comparison_handler(uint8_t* packet)
{
    char user_input;
    printf("[-] Confirming numeric comparison: %" PRIu32 " (Y/n): ", sm_event_numeric_comparison_request_get_passkey(packet));
    user_input = getchar();
    if (user_input == 'n') {
        sm_bonding_decline(sm_event_numeric_comparison_request_get_handle(packet));
    } else {
        sm_numeric_comparison_confirm(sm_event_numeric_comparison_request_get_handle(packet));
    }
    if (user_input != '\n') {
        putchar('\n');
    }
    return;
}

static void sm_passkey_input_handler(uint8_t* packet)
{
    char input_buffer[7];
    printf("[-] Passkey Input requested: ");
    fgets(input_buffer, sizeof(input_buffer), stdin);
    input_buffer[6] = '\0';
    uint32_t input_passkey = (uint32_t)atoi(input_buffer);
    printf("[-] Sending passkey %" PRIu32 "\n", input_passkey);
    sm_passkey_input(sm_event_passkey_input_number_get_handle(packet), input_passkey);
}

static inline void central_sm_pairing_setup(void)
{
    // setup SM
    sm_setup(profile_data_central);

    // register handler
    hci_event_callback_registration.callback = &central_hci_packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);

    sm_event_callback_registration.callback = &central_sm_packet_handler;
    sm_add_event_handler(&sm_event_callback_registration);

    // Configuration
    sm_config();
}

static inline void peripheral_sm_pairing_setup(void)
{
    // setup SM
    sm_setup(profile_data_peripheral);

    // setup advertisements
    uint16_t adv_int_min = 0x0030;
    uint16_t adv_int_max = 0x0030;
    uint8_t adv_type = 0;
    bd_addr_t null_addr;
    memset(null_addr, 0, 6);
    gap_advertisements_set_params(adv_int_min, adv_int_max, adv_type, 0, null_addr, 0x07, 0x00);
    gap_advertisements_set_data(adv_data_len, (uint8_t*)adv_data);
    gap_advertisements_enable(1);

    // register handler
    hci_event_callback_registration.callback = &peripheral_hci_packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);

    sm_event_callback_registration.callback = &peripheral_sm_packet_handler;
    sm_add_event_handler(&sm_event_callback_registration);

    // Configuration
    sm_config();
}

static inline void device_console_setup(void)
{
    sm_setup(profile_data_central);

    // register handler
    hci_event_callback_registration.callback = &console_hci_packet_handler;
    hci_add_event_handler(&hci_event_callback_registration);

    sm_config();
}

static inline void print_advertisment(uint8_t* packet)
{
    static const char* ad_types[] = {
        "",
        "Flags",
        "Incomplete 16-bit UUIDs",
        "Complete 16-bit UUIDs",
        "Incomplete 32-bit UUIDs",
        "Complete 32-bit UUIDs",
        "Incomplete 128-bit UUIDs",
        "Complete 128-bit UUIDs",
        "Short Name",
        "Complete Name",
        "Tx Power Level",
        "",
        "",
        "Class of Device",
        "Simple Pairing Hash C",
        "Simple Pairing Randomizer R",
        "Device ID",
        "Security Manager TK Value",
        "Slave Connection Interval Range",
        "",
        "16-bit Solicitation UUIDs",
        "128-bit Solicitation UUIDs",
        "Service Data",
        "Public Target Address",
        "Random Target Address",
        "Appearance",
        "Advertising Interval"
    };

    static uint32_t index = 0;
    bd_addr_t addr;
    gap_event_advertising_report_get_address(packet, addr);

    const int8_t rssi = (int8_t)gap_event_advertising_report_get_rssi(packet);
    const uint8_t ad_len = gap_event_advertising_report_get_data_length(packet);
    const uint8_t* ad_data = gap_event_advertising_report_get_data(packet);

    printf("   %u. %s (%-3d dBm)", ++index, bd_addr_to_str(addr), rssi);

    ad_context_t context;
    bd_addr_t address;
    uint8_t uuid_128[16];
    for (ad_iterator_init(&context, ad_len, ad_data); ad_iterator_has_more(&context); ad_iterator_next(&context)) {
        uint8_t data_type = ad_iterator_get_data_type(&context);
        uint8_t size = ad_iterator_get_data_len(&context);
        const uint8_t* data = ad_iterator_get_data(&context);

        if (data_type > 0 && data_type < 0x1B) {
            printf(" - %s: ", ad_types[data_type]);
        }
        uint8_t i;
        switch (data_type) {
        case BLUETOOTH_DATA_TYPE_FLAGS:
            printf("0x%02x", data[0]);
            break;
        case BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:
        case BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:
        case BLUETOOTH_DATA_TYPE_LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS:
            for (i = 0; i < size; i += 2) {
                printf("%02X ", little_endian_read_16(data, i));
            }
            break;
        case BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:
        case BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:
        case BLUETOOTH_DATA_TYPE_LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS:
            for (i = 0; i < size; i += 4) {
                printf("%04" PRIX32, little_endian_read_32(data, i));
            }
            break;
        case BLUETOOTH_DATA_TYPE_INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:
        case BLUETOOTH_DATA_TYPE_COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:
        case BLUETOOTH_DATA_TYPE_LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS:
            reverse_128(data, uuid_128);
            printf("%s", uuid128_to_str(uuid_128));
            break;
        case BLUETOOTH_DATA_TYPE_SHORTENED_LOCAL_NAME:
        case BLUETOOTH_DATA_TYPE_COMPLETE_LOCAL_NAME:
            for (i = 0; i < size; i++) {
                printf("%c", (char)(data[i]));
            }
            break;
        case BLUETOOTH_DATA_TYPE_TX_POWER_LEVEL:
            printf("%d dBm", *(int8_t*)data);
            break;
        case BLUETOOTH_DATA_TYPE_SLAVE_CONNECTION_INTERVAL_RANGE:
            printf("Connection Interval Min = %u ms, Max = %u ms", little_endian_read_16(data, 0) * 5 / 4,
                little_endian_read_16(data, 2) * 5 / 4);
            break;
        case BLUETOOTH_DATA_TYPE_SERVICE_DATA:
            printf_hexdump(data, size);
            break;
        case BLUETOOTH_DATA_TYPE_PUBLIC_TARGET_ADDRESS:
        case BLUETOOTH_DATA_TYPE_RANDOM_TARGET_ADDRESS:
            reverse_bd_addr(data, address);
            printf("%s", bd_addr_to_str(address));
            break;
        case BLUETOOTH_DATA_TYPE_APPEARANCE:
            // https://developer.bluetooth.org/gatt/characteristics/Pages/CharacteristicViewer.aspx?u=org.bluetooth.characteristic.gap.appearance.xml
            printf("%02X", little_endian_read_16(data, 0));
            break;
        case BLUETOOTH_DATA_TYPE_ADVERTISING_INTERVAL:
            printf("%u ms", little_endian_read_16(data, 0) * 5 / 8);
            break;
        case BLUETOOTH_DATA_TYPE_3D_INFORMATION_DATA:
            printf_hexdump(data, size);
            break;
        case BLUETOOTH_DATA_TYPE_MANUFACTURER_SPECIFIC_DATA:
        case BLUETOOTH_DATA_TYPE_CLASS_OF_DEVICE:
        case BLUETOOTH_DATA_TYPE_SIMPLE_PAIRING_HASH_C:
        case BLUETOOTH_DATA_TYPE_SIMPLE_PAIRING_RANDOMIZER_R:
        case BLUETOOTH_DATA_TYPE_DEVICE_ID:
        case BLUETOOTH_DATA_TYPE_SECURITY_MANAGER_OUT_OF_BAND_FLAGS:
        default:
            break;
        }
    }
    printf("\n");
}

static void central_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size)
{
    UNUSED(channel);
    UNUSED(size);

    if (packet_type != HCI_EVENT_PACKET)
        return;
    hci_con_handle_t con_handle;
    uint8_t status;

    switch (hci_event_packet_get_type(packet)) {
    case BTSTACK_EVENT_STATE:
        // BTstack activated, get started
        if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING) {
            printf("[-] Start scaning!\n");
            gap_set_scan_parameters(1, 0x0030, 0x0030);
            gap_start_scan();
        }
        break;
    case GAP_EVENT_ADVERTISING_REPORT: {
        bd_addr_t address;
        gap_event_advertising_report_get_address(packet, address);
        uint8_t address_type = gap_event_advertising_report_get_address_type(packet);
        uint8_t length = gap_event_advertising_report_get_data_length(packet);
        const uint8_t* data = gap_event_advertising_report_get_data(packet);

        print_advertisment(packet);

        if (0 == memcmp(address, remote_addr, 6)) {
            printf("[-] Found remote with address %s, connecting...\n", bd_addr_to_str(address));
        } else if (ad_data_contains_uuid16(length, (uint8_t*)data, REMOTE_SERVICE)) {
            printf("[-] Found remote with UUID %04x, connecting...\n", REMOTE_SERVICE);
        } else {
            break;
        }

        gap_stop_scan();
        gap_connect(address, address_type);
        break;
    }
    case HCI_EVENT_META_GAP:
        // wait for connection complete
        if (hci_event_gap_meta_get_subevent_code(packet) != GAP_SUBEVENT_LE_CONNECTION_COMPLETE)
            break;
        con_handle = gap_subevent_le_connection_complete_get_connection_handle(packet);
        printf("[*(%lld)] Connection complete\n", get_microsecond_timestamp());

        // for testing, choose one of the following actions

        // manually start pairing
        sm_request_pairing(con_handle);

        // gatt client request to authenticated characteristic in sm_pairing_peripheral (short cut, uses hard-coded value handle)
        // gatt_client_read_value_of_characteristic_using_value_handle(&hci_packet_handler, con_handle, 0x0009);

        // general gatt client request to trigger mandatory authentication
        // gatt_client_discover_primary_services(&hci_packet_handler, con_handle);
        break;
    case GATT_EVENT_QUERY_COMPLETE:
        status = gatt_event_query_complete_get_att_status(packet);
        switch (status) {
        case ATT_ERROR_INSUFFICIENT_ENCRYPTION:
            printf("[-] GATT Query result: Insufficient Encryption\n");
            break;
        case ATT_ERROR_INSUFFICIENT_AUTHENTICATION:
            printf("[-] GATT Query result: Insufficient Authentication\n");
            break;
        case ATT_ERROR_BONDING_INFORMATION_MISSING:
            printf("[-] GATT Query result: Bonding Information Missing\n");
            break;
        case ATT_ERROR_SUCCESS:
            printf("[-] GATT Query result: OK\n");
            break;
        default:
            printf("[-] GATT Query result: 0x%02x\n", gatt_event_query_complete_get_att_status(packet));
            break;
        }
        break;
    default:
        break;
    }
}

static void central_sm_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size)
{
    UNUSED(channel);
    UNUSED(size);

    if (packet_type != HCI_EVENT_PACKET)
        return;

    bd_addr_t addr;
    bd_addr_type_t addr_type;

    switch (hci_event_packet_get_type(packet)) {
    case SM_EVENT_JUST_WORKS_REQUEST:
        printf("[-] Just works requested\n");
        sm_just_works_confirm(sm_event_just_works_request_get_handle(packet));
        break;
    case SM_EVENT_NUMERIC_COMPARISON_REQUEST:
        sm_numeric_comparison_handler(packet);
        break;
    case SM_EVENT_PASSKEY_DISPLAY_NUMBER:
        printf("[-] Display Passkey: %" PRIu32 "\n", sm_event_passkey_display_number_get_passkey(packet));
        break;
    case SM_EVENT_PASSKEY_INPUT_NUMBER:
        sm_passkey_input_handler(packet);
        break;
    case SM_EVENT_PAIRING_STARTED:
        printf("[-] Pairing started\n");
        break;
    case SM_EVENT_PAIRING_COMPLETE:
        switch (sm_event_pairing_complete_get_status(packet)) {
        case ERROR_CODE_SUCCESS:
            printf("[-] Pairing complete, success\n");
            break;
        case ERROR_CODE_CONNECTION_TIMEOUT:
            printf("[-] Pairing failed, timeout\n");
            break;
        case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
            printf("[-] Pairing failed, disconnected\n");
            break;
        case ERROR_CODE_AUTHENTICATION_FAILURE:
            printf("[-] Pairing failed, authentication failure with reason = %u\n", sm_event_pairing_complete_get_reason(packet));
            break;
        default:
            break;
        }
        break;
    case SM_EVENT_REENCRYPTION_STARTED:
        sm_event_reencryption_complete_get_address(packet, addr);
        printf("[-] Bonding information exists for addr type %u, identity addr %s -> start re-encryption\n",
            sm_event_reencryption_started_get_addr_type(packet), bd_addr_to_str(addr));
        break;
    case SM_EVENT_REENCRYPTION_COMPLETE:
        switch (sm_event_reencryption_complete_get_status(packet)) {
        case ERROR_CODE_SUCCESS:
            printf("[*(%lld)] Re-encryption complete, success\n", get_microsecond_timestamp());
            break;
        case ERROR_CODE_CONNECTION_TIMEOUT:
            printf("[-] Re-encryption failed, timeout\n");
            break;
        case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
            printf("[-] Re-encryption failed, disconnected\n");
            break;
        case ERROR_CODE_PIN_OR_KEY_MISSING:
            printf("[-] Re-encryption failed, bonding information missing\n\n");
            printf("[-] Assuming remote lost bonding information\n");
            printf("[-] Deleting local bonding information and start new pairing...\n");
            sm_event_reencryption_complete_get_address(packet, addr);
            addr_type = sm_event_reencryption_started_get_addr_type(packet);
            gap_delete_bonding(addr_type, addr);
            sm_request_pairing(sm_event_reencryption_complete_get_handle(packet));
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
}

static void peripheral_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size)
{
    UNUSED(channel);
    UNUSED(size);

    if (packet_type != HCI_EVENT_PACKET)
        return;

    hci_con_handle_t con_handle;

    switch (hci_event_packet_get_type(packet)) {
    case HCI_EVENT_META_GAP:
        switch (hci_event_gap_meta_get_subevent_code(packet)) {
        case GAP_SUBEVENT_LE_CONNECTION_COMPLETE:
            printf("[-] Connection complete\n");
            con_handle = gap_subevent_le_connection_complete_get_connection_handle(packet);
            UNUSED(con_handle);

            // for testing, choose one of the following actions

            // manually start pairing
            // sm_request_pairing(con_handle);

            // gatt client request to authenticated characteristic in sm_pairing_central (short cut, uses hard-coded value handle)
            // gatt_client_read_value_of_characteristic_using_value_handle(&packet_handler, con_handle, 0x0009);

            // general gatt client request to trigger mandatory authentication
            // gatt_client_discover_primary_services(&packet_handler, con_handle);
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
}

static void peripheral_sm_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size)
{
    UNUSED(channel);
    UNUSED(size);

    if (packet_type != HCI_EVENT_PACKET)
        return;

    hci_con_handle_t con_handle;
    bd_addr_t addr;
    bd_addr_type_t addr_type;
    uint8_t status;

    switch (hci_event_packet_get_type(packet)) {
    case HCI_EVENT_META_GAP:
        switch (hci_event_gap_meta_get_subevent_code(packet)) {
        case GAP_SUBEVENT_LE_CONNECTION_COMPLETE:
            printf("[-] Connection complete\n");
            con_handle = gap_subevent_le_connection_complete_get_connection_handle(packet);
            UNUSED(con_handle);

            // for testing, choose one of the following actions

            // manually start pairing
            // sm_request_pairing(con_handle);

            // gatt client request to authenticated characteristic in sm_pairing_central (short cut, uses hard-coded value handle)
            // gatt_client_read_value_of_characteristic_using_value_handle(&packet_handler, con_handle, 0x0009);

            // general gatt client request to trigger mandatory authentication
            // gatt_client_discover_primary_services(&packet_handler, con_handle);
            break;
        default:
            break;
        }
        break;
    case SM_EVENT_JUST_WORKS_REQUEST:
        printf("[-] Just Works requested\n");
        sm_just_works_confirm(sm_event_just_works_request_get_handle(packet));
        break;
    case SM_EVENT_NUMERIC_COMPARISON_REQUEST:
        sm_numeric_comparison_handler(packet);
        break;
    case SM_EVENT_PASSKEY_DISPLAY_NUMBER:
        printf("[-] Display Passkey: %" PRIu32 "\n", sm_event_passkey_display_number_get_passkey(packet));
        break;
    case SM_EVENT_PASSKEY_INPUT_NUMBER:
        sm_passkey_input_handler(packet);
        break;
    case SM_EVENT_IDENTITY_CREATED:
        sm_event_identity_created_get_identity_address(packet, addr);
        printf("[-] Identity created: type %u address %s\n", sm_event_identity_created_get_identity_addr_type(packet), bd_addr_to_str(addr));
        break;
    case SM_EVENT_IDENTITY_RESOLVING_SUCCEEDED:
        sm_event_identity_resolving_succeeded_get_identity_address(packet, addr);
        printf("[-] Identity resolved: type %u address %s\n", sm_event_identity_resolving_succeeded_get_identity_addr_type(packet), bd_addr_to_str(addr));
        break;
    case SM_EVENT_IDENTITY_RESOLVING_FAILED:
        sm_event_identity_created_get_address(packet, addr);
        printf("[-] Identity resolving failed\n");
        break;
    case SM_EVENT_PAIRING_STARTED:
        printf("[-] Pairing started\n");
        break;
    case SM_EVENT_PAIRING_COMPLETE:
        switch (sm_event_pairing_complete_get_status(packet)) {
        case ERROR_CODE_SUCCESS:
            printf("[-] Pairing complete, success\n");
            break;
        case ERROR_CODE_CONNECTION_TIMEOUT:
            printf("[-] Pairing failed, timeout\n");
            break;
        case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
            printf("[-] Pairing failed, disconnected\n");
            break;
        case ERROR_CODE_AUTHENTICATION_FAILURE:
            printf("[-] Pairing failed, authentication failure with reason = %u\n", sm_event_pairing_complete_get_reason(packet));
            break;
        default:
            break;
        }
        break;
    case SM_EVENT_REENCRYPTION_STARTED:
        sm_event_reencryption_complete_get_address(packet, addr);
        printf("[-] Bonding information exists for addr type %u, identity addr %s -> re-encryption started\n",
            sm_event_reencryption_started_get_addr_type(packet), bd_addr_to_str(addr));
        break;
    case SM_EVENT_REENCRYPTION_COMPLETE:
        switch (sm_event_reencryption_complete_get_status(packet)) {
        case ERROR_CODE_SUCCESS:
            printf("[-] Re-encryption complete, success\n");
            break;
        case ERROR_CODE_CONNECTION_TIMEOUT:
            printf("[-] Re-encryption failed, timeout\n");
            break;
        case ERROR_CODE_REMOTE_USER_TERMINATED_CONNECTION:
            printf("[-] Re-encryption failed, disconnected\n");
            break;
        case ERROR_CODE_PIN_OR_KEY_MISSING:
            printf("[-] Re-encryption failed, bonding information missing\n\n");
            printf("[-] Assuming remote lost bonding information\n");
            printf("[-] Deleting local bonding information to allow for new pairing...\n");
            sm_event_reencryption_complete_get_address(packet, addr);
            addr_type = sm_event_reencryption_started_get_addr_type(packet);
            gap_delete_bonding(addr_type, addr);
            break;
        default:
            break;
        }
        break;
    case GATT_EVENT_QUERY_COMPLETE:
        status = gatt_event_query_complete_get_att_status(packet);
        switch (status) {
        case ATT_ERROR_INSUFFICIENT_ENCRYPTION:
            printf("[-] GATT Query failed, Insufficient Encryption\n");
            break;
        case ATT_ERROR_INSUFFICIENT_AUTHENTICATION:
            printf("[-] GATT Query failed, Insufficient Authentication\n");
            break;
        case ATT_ERROR_BONDING_INFORMATION_MISSING:
            printf("[-] GATT Query failed, Bonding Information Missing\n");
            break;
        case ATT_ERROR_SUCCESS:
            printf("[-] GATT Query successful\n");
            break;
        default:
            printf("[-] GATT Query failed, status 0x%02x\n", gatt_event_query_complete_get_att_status(packet));
            break;
        }
        break;
    default:
        break;
    }
}

static void sm_remove_le_device_db_entry(uint16_t i)
{
    le_device_db_remove(i);
#ifdef ENABLE_LE_PRIVACY_ADDRESS_RESOLUTION
    // to remove an entry from the resolving list requires its identity address, which was already deleted
    // fully reload resolving list instead
    gap_load_resolving_list_from_le_device_db();
#endif
}

static void device_print_help(void)
{
    printf("Help:\n");
    printf("  l    List all bounded devices.\n");
    printf("  d    Delete bounded device(s).\n");
    printf("       - d all\tDelete all bounded devices.\n");
    printf("       - d <index>\tDelete the device with the specified index.\n");
    printf("       - d <addr>\tDelete the device with the specified address.\n");
    printf("  h    Show this help.\n");
    printf("  q    Quit.\n");
}

static void device_print_devices(void)
{
    for (int i = 0; i < le_device_db_max_count(); i++) {
        bd_addr_t db_address;
        int db_address_type = BD_ADDR_TYPE_UNKNOWN;
        le_device_db_info(i, &db_address_type, db_address, NULL);
        if (db_address_type == BD_ADDR_TYPE_UNKNOWN) {
            continue;
        }
        printf("  %-2u: %s\n", i, bd_addr_to_str(db_address));
    }
}

static void device_delete_all(void)
{   
    int count = 0;
    for (int i = 0; i < le_device_db_max_count(); i++) {
        bd_addr_t db_address;
        int db_address_type = BD_ADDR_TYPE_UNKNOWN;
        le_device_db_info(i, &db_address_type, db_address, NULL);
        if (db_address_type == BD_ADDR_TYPE_UNKNOWN) {
            continue;
        }
        sm_remove_le_device_db_entry(i);
        count++;
    }
    printf("  Deleted %u device(s).\n", count);
}

static void device_delete_address(bd_addr_t address)
{
    for (int i = 0; i < le_device_db_max_count(); i++) {
        bd_addr_t db_address;
        int db_address_type = BD_ADDR_TYPE_UNKNOWN;
        le_device_db_info(i, &db_address_type, db_address, NULL);
        if (db_address_type == BD_ADDR_TYPE_UNKNOWN) {
            continue;
        }
        if (memcmp(db_address, address, 6) == 0) {
            sm_remove_le_device_db_entry(i);
            printf("  Deleted device with address %s.\n", bd_addr_to_str(address));
            return;
        }
    }
    printf("  Device with address %s not found.\n", bd_addr_to_str(address));
}

static void device_delete_index(int index)
{
    if (index < 0 || index >= le_device_db_max_count()) {
        printf("  Invalid device index %d.\n", index);
        return;
    }
    sm_remove_le_device_db_entry(index);
    printf("  Deleted device with index %u.\n", index);
}

static int device_console(void)
{
    printf("Command (h for help): ");

    bd_addr_t address;
    char buffer[256] = { 0 };
    char* command = buffer;
    fgets(buffer, sizeof(buffer), stdin);
    buffer[255] = '\0';

    while (*command == ' ') {
        command++;
    }
    for (char* p = command; *p != '\0'; p++) {
        if (*p == '\n' || *p == '\r') {
            *p = '\0';
            break;
        }
    }

    switch (*command) {
    case 'q':
        printf("Goodbye!\n");
        return 0;
    case 'h':
        device_print_help();
        break;
    case 'l':
        device_print_devices();
        break;
    case 'd':
        command++;
        while (*command == ' ') {
            command++;
        }
        for (char* p = command; *p != '\0'; p++) {
            if (*p == ' ') {
                *p = '\0';
                break;
            }
        }
        if (strcmp(command, "all") == 0) {
            device_delete_all();
        } else if (sscanf_bd_addr(command, address)) {
            device_delete_address(address);
        } else {
            device_delete_index(atoi(command));
        }
        break;
    default:
        printf("Unknown command: '%s'\n", command);
        break;
    }
    return 1;
}

static void console_hci_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t* packet, uint16_t size)
{
    UNUSED(channel);
    UNUSED(size);

    if (packet_type != HCI_EVENT_PACKET)
        return;

    int ret;
    switch (hci_event_packet_get_type(packet)) {
    case BTSTACK_EVENT_STATE:
        // BTstack activated, get started
        if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING) {
            printf("============================================================\n");
            printf("        \033[0;32mWelcome to Bluetooth Device Console.\033[0m      \n");
            printf("============================================================\n");
            do {
                ret = device_console();
            } while (ret);
            exit(0);
        }
        break;
    default:
        break;
    }
}

static const char* get_io_capability_description(io_capability_t capability)
{
    switch (capability) {
    case IO_CAPABILITY_DISPLAY_ONLY:
        return "Display-Only (0)";
    case IO_CAPABILITY_DISPLAY_YES_NO:
        return "Display-Yes-No (1)";
    case IO_CAPABILITY_KEYBOARD_ONLY:
        return "Keyboard-Only (2)";
    case IO_CAPABILITY_NO_INPUT_NO_OUTPUT:
        return "No-Input-No-Output (3)";
    case IO_CAPABILITY_KEYBOARD_DISPLAY:
        return "Keyboard-Display (4)";
    default:
        return "Unknown Capability";
    }
}

static int parse_arugments(int argc, const char* argv[])
{
    int opt;
    struct option long_options[] = {
        { "central", no_argument, 0, 'C' },
        { "peripheral", no_argument, 0, 'P' },
        { "io-capability", required_argument, 0, 'I' },
        { "remote-address", required_argument, 0, 'R' },
        { "device-console", no_argument, 0, 'D' },
        { 0, 0, 0, 0 }
    };

    optind = 1;
    while ((opt = getopt_long(argc, (char* const*)argv, "CPI:R:D", long_options, NULL)) != -1) {
        switch (opt) {
        case 'C':
            if (role == RO_PERIPHERAL) {
                fprintf(stderr, "Error: Option '-C' (--central) and '-P' (--peripheral) are mutually exclusive.\n");
                fprintf(stderr, "Hint: Specify only one of these options. For example, use '-C' for Central role or '-P' for Peripheral role.\n");
                return 1;
            }
            role = RO_CENTRAL;
            break;
        case 'P':
            if (role == RO_CENTRAL) {
                fprintf(stderr, "Error: Option '-P' (--peripheral) and '-C' (--central) are mutually exclusive.\n");
                fprintf(stderr, "Hint: Specify only one of these options. For example, use '-P' for Peripheral role or '-C' for Central role.\n");
                return 1;
            }
            role = RO_PERIPHERAL;
            break;
        case 'I': {
            int capability = atoi(optarg);
            if (capability < IO_CAPABILITY_DISPLAY_ONLY || capability > IO_CAPABILITY_KEYBOARD_DISPLAY) {
                fprintf(stderr, "Error: Invalid value '%s' for '-I' (--io-capability).\n", optarg);
                fprintf(stderr, "Hint: Valid values are:\n");
                fprintf(stderr, "  0: Display-Only (default)\n");
                fprintf(stderr, "  1: Display-Yes-No\n");
                fprintf(stderr, "  2: Keyboard-Only\n");
                fprintf(stderr, "  3: No-Input-No-Output\n");
                fprintf(stderr, "  4: Keyboard-Display\n");
                return 1;
            }
            io_capability = (io_capability_t)capability;
            break;
        }
        case 'R':
            if (!sscanf_bd_addr(optarg, remote_addr)) {
                fprintf(stderr, "Error: Invalid value '%s' for '-R' (--remote-address).\n", optarg);
                fprintf(stderr, "Hint: Specify a valid Bluetooth address in the format '01:23:45:67:89:AB'.\n");
                return 1;
            }
            break;
        case 'D':
            flag_device_console = true;
            break;
        default:
            fprintf(stderr, "Invalid option or missing argument.\n");
            fprintf(stderr, "Usage:\n");
            fprintf(stderr, "  -C, --central       Set device role to Central (mutually exclusive with -P).\n");
            fprintf(stderr, "  -P, --peripheral    Set device role to Peripheral (mutually exclusive with -C).\n");
            fprintf(stderr, "  -I, --io-capability Specify IO capability (optional, default is 0). Valid values:\n");
            fprintf(stderr, "      0: Display-Only (default)\n");
            fprintf(stderr, "      1: Display-Yes-No\n");
            fprintf(stderr, "      2: Keyboard-Only\n");
            fprintf(stderr, "      3: No-Input-No-Output\n");
            fprintf(stderr, "      4: Keyboard-Display\n");
            fprintf(stderr, "  -R, --remote-address Specify remote address to connect.\n");
            fprintf(stderr, "  -D, --device-console Enable device console.\n");
            fprintf(stderr, "\nExample:\n");
            fprintf(stderr, "  %s -C -I 1\n", argv[0]);
            fprintf(stderr, "  %s -P\n", argv[0]);
            return 1;
        }
    }

    if (flag_device_console) {
        return 0;
    }

    if (role != RO_CENTRAL && role != RO_PERIPHERAL) {
        fprintf(stderr, "Error: Either '-C' (--central) or '-P' (--peripheral) must be specified.\n");
        fprintf(stderr, "Hint: Specify one role using '-C' or '-P'. For example:\n");
        fprintf(stderr, "  - Use '-C' for a Central role.\n");
        fprintf(stderr, "  - Use '-P' for a Peripheral role.\n");
        return 1;
    }

    printf("Device:\n");
    if (role == RO_CENTRAL) {
        printf("- %-7s Central\n", "Role:");
    } else if (role == RO_PERIPHERAL) {
        printf("- %-7s Peripheral\n", "Role:");
    }
    printf("- %-7s %s\n", "IOCap:", get_io_capability_description(io_capability));

    return 0;
}

int btstack_main(int argc, const char* argv[]);
int btstack_main(int argc, const char* argv[])
{
    // parse command line parameters
    if (parse_arugments(argc, argv)) {
        exit(1);
    }

    // run the pairing setup
    if (flag_device_console) {
        device_console_setup();
    } else if (role == RO_CENTRAL) {
        central_sm_pairing_setup();
    } else if (role == RO_PERIPHERAL) {
        peripheral_sm_pairing_setup();
    } else {
        printf("Error: Unknown role\n");
        exit(1);
    }

    // turn on!
    hci_power_control(HCI_POWER_ON);

    return 0;
}