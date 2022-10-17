use std::time::Duration;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use ferrisetw::provider::Provider;
use ferrisetw::provider::EventFilter;
use ferrisetw::provider::TraceFlags;
use ferrisetw::parser::Parser;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::native::etw_types::EventRecord;
use ferrisetw::trace::TraceTrait;
use ferrisetw::trace::UserTrace;
use ferrisetw::parser::TryParse;
use ferrisetw::trace::TraceBaseTrait;
use ferrisetw::schema::Schema;


static N_EVENTS: AtomicU32 = AtomicU32::new(0);

fn dns_etw_callback(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!(
                "Unable to get the ETW schema for a DNS event: {:?}",
                err
            );
            return;
        },

        Ok(schema) => {
            parse_etw_event(&schema, record);
        },
    }
}

fn parse_etw_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    // let event_timestamp = filetime_to_datetime(schema.timestamp());

    let requested_fqdn: Option<String> = parser
        .try_parse("QueryName")
        .ok();
    let query_type: Option<u32> = parser
        .try_parse("QueryType")
        .ok();
    let query_options: Option<u64> = parser
        .try_parse("QueryOptions")
        .ok();
    let query_status: Option<u32> = parser
        .try_parse("QueryStatus")
        .or_else(|_err| parser.try_parse("Status"))
        .ok();
    let query_results: Option<String> = parser
        .try_parse("QueryResults")
        .ok();

    println!("{:4} {:4}  {:16} {:2} {:10} {}",
        record.event_id(),
        query_status.map(|u| u.to_string()).unwrap_or_default(),
        query_options.map(|u| format!("{:16x}", u)).unwrap_or_default(),
        query_type.map(|u| format!("{:2}", u)).unwrap_or_default(),
        requested_fqdn.map(|s| first(&s, 10).to_owned()).unwrap_or_default(),
        query_results.map(|s| first(&s, 30).to_owned()).unwrap_or_default(),
    );
}

fn main() {
    let dns_provider = Provider
        ::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_callback(
            move |record: &EventRecord, schema_locator: &SchemaLocator| {
                dns_etw_callback(record, schema_locator);
            },
        )
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let mut trace = UserTrace::new()
        .enable(dns_provider)
        .start()
        .unwrap()
        .process()
        .unwrap();

    println!("ID   Status Options         Ty Name       Results");

    std::thread::sleep(Duration::new(120, 0));
    trace.stop();

    println!("Done: {:?} events", N_EVENTS);
}



fn dns_error_description(error: i32) -> String {
    // See https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--9000-11999-
    match error {
        9001 => String::from("DNS_ERROR_RCODE_FORMAT_ERROR"),
        9002 => String::from("DNS_ERROR_RCODE_SERVER_FAILURE"),
        9003 => String::from("DNS_ERROR_RCODE_NAME_ERROR"),
        9004 => String::from("DNS_ERROR_RCODE_NOT_IMPLEMENTED"),
        9005 => String::from("DNS_ERROR_RCODE_REFUSED"),
        9006 => String::from("DNS_ERROR_RCODE_YXDOMAIN"),
        9007 => String::from("DNS_ERROR_RCODE_YXRRSET"),
        9008 => String::from("DNS_ERROR_RCODE_NXRRSET"),
        9009 => String::from("DNS_ERROR_RCODE_NOTAUTH"),
        9010 => String::from("DNS_ERROR_RCODE_NOTZONE"),
        9016 => String::from("DNS_ERROR_RCODE_BADSIG"),
        9017 => String::from("DNS_ERROR_RCODE_BADKEY"),
        9018 => String::from("DNS_ERROR_RCODE_BADTIME"),
        9101 => String::from("DNS_ERROR_KEYMASTER_REQUIRED"),
        9102 => String::from("DNS_ERROR_NOT_ALLOWED_ON_SIGNED_ZONE"),
        9103 => String::from("DNS_ERROR_NSEC3_INCOMPATIBLE_WITH_RSA_SHA1"),
        9104 => String::from("DNS_ERROR_NOT_ENOUGH_SIGNING_KEY_DESCRIPTORS"),
        9105 => String::from("DNS_ERROR_UNSUPPORTED_ALGORITHM"),
        9106 => String::from("DNS_ERROR_INVALID_KEY_SIZE"),
        9107 => String::from("DNS_ERROR_SIGNING_KEY_NOT_ACCESSIBLE"),
        9108 => String::from("DNS_ERROR_KSP_DOES_NOT_SUPPORT_PROTECTION"),
        9109 => String::from("DNS_ERROR_UNEXPECTED_DATA_PROTECTION_ERROR"),
        9110 => String::from("DNS_ERROR_UNEXPECTED_CNG_ERROR"),
        9111 => String::from("DNS_ERROR_UNKNOWN_SIGNING_PARAMETER_VERSION"),
        9112 => String::from("DNS_ERROR_KSP_NOT_ACCESSIBLE"),
        9113 => String::from("DNS_ERROR_TOO_MANY_SKDS"),
        9114 => String::from("DNS_ERROR_INVALID_ROLLOVER_PERIOD"),
        9115 => String::from("DNS_ERROR_INVALID_INITIAL_ROLLOVER_OFFSET"),
        9116 => String::from("DNS_ERROR_ROLLOVER_IN_PROGRESS"),
        9117 => String::from("DNS_ERROR_STANDBY_KEY_NOT_PRESENT"),
        9118 => String::from("DNS_ERROR_NOT_ALLOWED_ON_ZSK"),
        9119 => String::from("DNS_ERROR_NOT_ALLOWED_ON_ACTIVE_SKD"),
        9120 => String::from("DNS_ERROR_ROLLOVER_ALREADY_QUEUED"),
        9121 => String::from("DNS_ERROR_NOT_ALLOWED_ON_UNSIGNED_ZONE"),
        9122 => String::from("DNS_ERROR_BAD_KEYMASTER"),
        9123 => String::from("DNS_ERROR_INVALID_SIGNATURE_VALIDITY_PERIOD"),
        9124 => String::from("DNS_ERROR_INVALID_NSEC3_ITERATION_COUNT"),
        9125 => String::from("DNS_ERROR_DNSSEC_IS_DISABLED"),
        9126 => String::from("DNS_ERROR_INVALID_XML"),
        9127 => String::from("DNS_ERROR_NO_VALID_TRUST_ANCHORS"),
        9128 => String::from("DNS_ERROR_ROLLOVER_NOT_POKEABLE"),
        9129 => String::from("DNS_ERROR_NSEC3_NAME_COLLISION"),
        9130 => String::from("DNS_ERROR_NSEC_INCOMPATIBLE_WITH_NSEC3_RSA_SHA1"),
        9501 => String::from("DNS_INFO_NO_RECORDS"),
        9502 => String::from("DNS_ERROR_BAD_PACKET"),
        9503 => String::from("DNS_ERROR_NO_PACKET"),
        9504 => String::from("DNS_ERROR_RCODE"),
        9505 => String::from("DNS_ERROR_UNSECURE_PACKET"),
        9506 => String::from("DNS_REQUEST_PENDING"),
        9551 => String::from("DNS_ERROR_INVALID_TYPE"),
        9552 => String::from("DNS_ERROR_INVALID_IP_ADDRESS"),
        9553 => String::from("DNS_ERROR_INVALID_PROPERTY"),
        9554 => String::from("DNS_ERROR_TRY_AGAIN_LATER"),
        9555 => String::from("DNS_ERROR_NOT_UNIQUE"),
        9556 => String::from("DNS_ERROR_NON_RFC_NAME"),
        9557 => String::from("DNS_STATUS_FQDN"),
        9558 => String::from("DNS_STATUS_DOTTED_NAME"),
        9559 => String::from("DNS_STATUS_SINGLE_PART_NAME"),
        9560 => String::from("DNS_ERROR_INVALID_NAME_CHAR"),
        9561 => String::from("DNS_ERROR_NUMERIC_NAME"),
        9562 => String::from("DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER"),
        9563 => String::from("DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION"),
        9564 => String::from("DNS_ERROR_CANNOT_FIND_ROOT_HINTS"),
        9565 => String::from("DNS_ERROR_INCONSISTENT_ROOT_HINTS"),
        9566 => String::from("DNS_ERROR_DWORD_VALUE_TOO_SMALL"),
        9567 => String::from("DNS_ERROR_DWORD_VALUE_TOO_LARGE"),
        9568 => String::from("DNS_ERROR_BACKGROUND_LOADING"),
        9569 => String::from("DNS_ERROR_NOT_ALLOWED_ON_RODC"),
        9570 => String::from("DNS_ERROR_NOT_ALLOWED_UNDER_DNAME"),
        9571 => String::from("DNS_ERROR_DELEGATION_REQUIRED"),
        9572 => String::from("DNS_ERROR_INVALID_POLICY_TABLE"),
        9601 => String::from("DNS_ERROR_ZONE_DOES_NOT_EXIST"),
        9602 => String::from("DNS_ERROR_NO_ZONE_INFO"),
        9603 => String::from("DNS_ERROR_INVALID_ZONE_OPERATION"),
        9604 => String::from("DNS_ERROR_ZONE_CONFIGURATION_ERROR"),
        9605 => String::from("DNS_ERROR_ZONE_HAS_NO_SOA_RECORD"),
        9606 => String::from("DNS_ERROR_ZONE_HAS_NO_NS_RECORDS"),
        9607 => String::from("DNS_ERROR_ZONE_LOCKED"),
        9608 => String::from("DNS_ERROR_ZONE_CREATION_FAILED"),
        9609 => String::from("DNS_ERROR_ZONE_ALREADY_EXISTS"),
        9610 => String::from("DNS_ERROR_AUTOZONE_ALREADY_EXISTS"),
        9611 => String::from("DNS_ERROR_INVALID_ZONE_TYPE"),
        9612 => String::from("DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP"),
        9613 => String::from("DNS_ERROR_ZONE_NOT_SECONDARY"),
        9614 => String::from("DNS_ERROR_NEED_SECONDARY_ADDRESSES"),
        9615 => String::from("DNS_ERROR_WINS_INIT_FAILED"),
        9616 => String::from("DNS_ERROR_NEED_WINS_SERVERS"),
        9617 => String::from("DNS_ERROR_NBSTAT_INIT_FAILED"),
        9618 => String::from("DNS_ERROR_SOA_DELETE_INVALID"),
        9619 => String::from("DNS_ERROR_FORWARDER_ALREADY_EXISTS"),
        9620 => String::from("DNS_ERROR_ZONE_REQUIRES_MASTER_IP"),
        9621 => String::from("DNS_ERROR_ZONE_IS_SHUTDOWN"),
        9622 => String::from("DNS_ERROR_ZONE_LOCKED_FOR_SIGNING"),
        9651 => String::from("DNS_ERROR_PRIMARY_REQUIRES_DATAFILE"),
        9652 => String::from("DNS_ERROR_INVALID_DATAFILE_NAME"),
        9653 => String::from("DNS_ERROR_DATAFILE_OPEN_FAILURE"),
        9654 => String::from("DNS_ERROR_FILE_WRITEBACK_FAILED"),
        9655 => String::from("DNS_ERROR_DATAFILE_PARSING"),
        9701 => String::from("DNS_ERROR_RECORD_DOES_NOT_EXIST"),
        9702 => String::from("DNS_ERROR_RECORD_FORMAT"),
        9703 => String::from("DNS_ERROR_NODE_CREATION_FAILED"),
        9704 => String::from("DNS_ERROR_UNKNOWN_RECORD_TYPE"),
        9705 => String::from("DNS_ERROR_RECORD_TIMED_OUT"),
        9706 => String::from("DNS_ERROR_NAME_NOT_IN_ZONE"),
        9707 => String::from("DNS_ERROR_CNAME_LOOP"),
        9708 => String::from("DNS_ERROR_NODE_IS_CNAME"),
        9709 => String::from("DNS_ERROR_CNAME_COLLISION"),
        9710 => String::from("DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT"),
        9711 => String::from("DNS_ERROR_RECORD_ALREADY_EXISTS"),
        9712 => String::from("DNS_ERROR_SECONDARY_DATA"),
        9713 => String::from("DNS_ERROR_NO_CREATE_CACHE_DATA"),
        9714 => String::from("DNS_ERROR_NAME_DOES_NOT_EXIST"),
        9715 => String::from("DNS_WARNING_PTR_CREATE_FAILED"),
        9716 => String::from("DNS_WARNING_DOMAIN_UNDELETED"),
        9717 => String::from("DNS_ERROR_DS_UNAVAILABLE"),
        9718 => String::from("DNS_ERROR_DS_ZONE_ALREADY_EXISTS"),
        9719 => String::from("DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE"),
        9720 => String::from("DNS_ERROR_NODE_IS_DNAME"),
        9721 => String::from("DNS_ERROR_DNAME_COLLISION"),
        9722 => String::from("DNS_ERROR_ALIAS_LOOP"),
        9751 => String::from("DNS_INFO_AXFR_COMPLETE"),
        9752 => String::from("DNS_ERROR_AXFR"),
        9753 => String::from("DNS_INFO_ADDED_LOCAL_WINS"),
        9801 => String::from("DNS_STATUS_CONTINUE_NEEDED"),
        9851 => String::from("DNS_ERROR_NO_TCPIP"),
        9852 => String::from("DNS_ERROR_NO_DNS_SERVERS"),
        9901 => String::from("DNS_ERROR_DP_DOES_NOT_EXIST"),
        9902 => String::from("DNS_ERROR_DP_ALREADY_EXISTS"),
        9903 => String::from("DNS_ERROR_DP_NOT_ENLISTED"),
        9904 => String::from("DNS_ERROR_DP_ALREADY_ENLISTED"),
        9905 => String::from("DNS_ERROR_DP_NOT_AVAILABLE"),
        9906 => String::from("DNS_ERROR_DP_FSMO_ERROR"),
        other @ _ => format!("Unknown DNS error {}", other)
    }
}


fn code_reason(mut x: u64) -> String {
    let mut disp = String::new();

    // if x & 0x0001 == 0x0001 {
    //     disp.push_str("| DNS_TYPE_A");
    //     x = x & !0x0001;
    // }
    // if x & 0x0002 == 0x0002 {
    //     disp.push_str("| DNS_TYPE_NS");
    //     x = x & !0x0002;
    // }
    // if x & 0x0003 == 0x0003 {
    //     disp.push_str("| DNS_TYPE_MD");
    //     x = x & !0x0003;
    // }
    // if x & 0x0004 == 0x0004 {
    //     disp.push_str("| DNS_TYPE_MF");
    //     x = x & !0x0004;
    // }
    // if x & 0x0005 == 0x0005 {
    //     disp.push_str("| DNS_TYPE_CNAME");
    //     x = x & !0x0005;
    // }
    // if x & 0x0006 == 0x0006 {
    //     disp.push_str("| DNS_TYPE_SOA");
    //     x = x & !0x0006;
    // }
    // if x & 0x0007 == 0x0007 {
    //     disp.push_str("| DNS_TYPE_MB");
    //     x = x & !0x0007;
    // }
    // if x & 0x0008 == 0x0008 {
    //     disp.push_str("| DNS_TYPE_MG");
    //     x = x & !0x0008;
    // }
    // if x & 0x0009 == 0x0009 {
    //     disp.push_str("| DNS_TYPE_MR");
    //     x = x & !0x0009;
    // }
    // if x & 0x000a == 0x000a {
    //     disp.push_str("| DNS_TYPE_NULL");
    //     x = x & !0x000a;
    // }
    // if x & 0x000b == 0x000b {
    //     disp.push_str("| DNS_TYPE_WKS");
    //     x = x & !0x000b;
    // }
    // if x & 0x000c == 0x000c {
    //     disp.push_str("| DNS_TYPE_PTR");
    //     x = x & !0x000c;
    // }
    // if x & 0x000d == 0x000d {
    //     disp.push_str("| DNS_TYPE_HINFO");
    //     x = x & !0x000d;
    // }
    // if x & 0x000e == 0x000e {
    //     disp.push_str("| DNS_TYPE_MINFO");
    //     x = x & !0x000e;
    // }
    // if x & 0x000f == 0x000f {
    //     disp.push_str("| DNS_TYPE_MX");
    //     x = x & !0x000f;
    // }
    // if x & 0x0010 == 0x0010 {
    //     disp.push_str("| DNS_TYPE_TEXT");
    //     x = x & !0x0010;
    // }
    // if x & 0x0011 == 0x0011 {
    //     disp.push_str("| DNS_TYPE_RP");
    //     x = x & !0x0011;
    // }
    // if x & 0x0012 == 0x0012 {
    //     disp.push_str("| DNS_TYPE_AFSDB");
    //     x = x & !0x0012;
    // }
    // if x & 0x0013 == 0x0013 {
    //     disp.push_str("| DNS_TYPE_X25");
    //     x = x & !0x0013;
    // }
    // if x & 0x0014 == 0x0014 {
    //     disp.push_str("| DNS_TYPE_ISDN");
    //     x = x & !0x0014;
    // }
    // if x & 0x0015 == 0x0015 {
    //     disp.push_str("| DNS_TYPE_RT");
    //     x = x & !0x0015;
    // }
    // if x & 0x0016 == 0x0016 {
    //     disp.push_str("| DNS_TYPE_NSAP");
    //     x = x & !0x0016;
    // }
    // if x & 0x0017 == 0x0017 {
    //     disp.push_str("| DNS_TYPE_NSAPPTR");
    //     x = x & !0x0017;
    // }
    // if x & 0x0018 == 0x0018 {
    //     disp.push_str("| DNS_TYPE_SIG");
    //     x = x & !0x0018;
    // }
    // if x & 0x0019 == 0x0019 {
    //     disp.push_str("| DNS_TYPE_KEY");
    //     x = x & !0x0019;
    // }
    // if x & 0x001a == 0x001a {
    //     disp.push_str("| DNS_TYPE_PX");
    //     x = x & !0x001a;
    // }
    // if x & 0x001b == 0x001b {
    //     disp.push_str("| DNS_TYPE_GPOS");
    //     x = x & !0x001b;
    // }
    // if x & 0x001c == 0x001c {
    //     disp.push_str("| DNS_TYPE_AAAA");
    //     x = x & !0x001c;
    // }
    // if x & 0x001d == 0x001d {
    //     disp.push_str("| DNS_TYPE_LOC");
    //     x = x & !0x001d;
    // }
    // if x & 0x001e == 0x001e {
    //     disp.push_str("| DNS_TYPE_NXT");
    //     x = x & !0x001e;
    // }
    // if x & 0x001f == 0x001f {
    //     disp.push_str("| DNS_TYPE_EID");
    //     x = x & !0x001f;
    // }
    // if x & 0x0020 == 0x0020 {
    //     disp.push_str("| DNS_TYPE_NIMLOC");
    //     x = x & !0x0020;
    // }
    // if x & 0x0021 == 0x0021 {
    //     disp.push_str("| DNS_TYPE_SRV");
    //     x = x & !0x0021;
    // }
    // if x & 0x0022 == 0x0022 {
    //     disp.push_str("| DNS_TYPE_ATMA");
    //     x = x & !0x0022;
    // }
    // if x & 0x0023 == 0x0023 {
    //     disp.push_str("| DNS_TYPE_NAPTR");
    //     x = x & !0x0023;
    // }
    // if x & 0x0024 == 0x0024 {
    //     disp.push_str("| DNS_TYPE_KX");
    //     x = x & !0x0024;
    // }
    // if x & 0x0025 == 0x0025 {
    //     disp.push_str("| DNS_TYPE_CERT");
    //     x = x & !0x0025;
    // }
    // if x & 0x0026 == 0x0026 {
    //     disp.push_str("| DNS_TYPE_A6");
    //     x = x & !0x0026;
    // }
    // if x & 0x0027 == 0x0027 {
    //     disp.push_str("| DNS_TYPE_DNAME");
    //     x = x & !0x0027;
    // }
    // if x & 0x0028 == 0x0028 {
    //     disp.push_str("| DNS_TYPE_SINK");
    //     x = x & !0x0028;
    // }
    // if x & 0x0029 == 0x0029 {
    //     disp.push_str("| DNS_TYPE_OPT");
    //     x = x & !0x0029;
    // }
    // if x & 0x002B == 0x002B {
    //     disp.push_str("| DNS_TYPE_DS");
    //     x = x & !0x002B;
    // }
    // if x & 0x002E == 0x002E {
    //     disp.push_str("| DNS_TYPE_RRSIG");
    //     x = x & !0x002E;
    // }
    // if x & 0x002F == 0x002F {
    //     disp.push_str("| DNS_TYPE_NSEC");
    //     x = x & !0x002F;
    // }
    // if x & 0x0030 == 0x0030 {
    //     disp.push_str("| DNS_TYPE_DNSKEY");
    //     x = x & !0x0030;
    // }
    // if x & 0x0031 == 0x0031 {
    //     disp.push_str("| DNS_TYPE_DHCID");
    //     x = x & !0x0031;
    // }
    // if x & 0x0064 == 0x0064 {
    //     disp.push_str("| DNS_TYPE_UINFO");
    //     x = x & !0x0064;
    // }
    // if x & 0x0065 == 0x0065 {
    //     disp.push_str("| DNS_TYPE_UID");
    //     x = x & !0x0065;
    // }
    // if x & 0x0066 == 0x0066 {
    //     disp.push_str("| DNS_TYPE_GID");
    //     x = x & !0x0066;
    // }
    // if x & 0x0067 == 0x0067 {
    //     disp.push_str("| DNS_TYPE_UNSPEC");
    //     x = x & !0x0067;
    // }
    // if x & 0x00f8 == 0x00f8 {
    //     disp.push_str("| DNS_TYPE_ADDRS");
    //     x = x & !0x00f8;
    // }
    // if x & 0x00f9 == 0x00f9 {
    //     disp.push_str("| DNS_TYPE_TKEY");
    //     x = x & !0x00f9;
    // }
    // if x & 0x00fa == 0x00fa {
    //     disp.push_str("| DNS_TYPE_TSIG");
    //     x = x & !0x00fa;
    // }
    // if x & 0x00fb == 0x00fb {
    //     disp.push_str("| DNS_TYPE_IXFR");
    //     x = x & !0x00fb;
    // }
    // if x & 0x00fc == 0x00fc {
    //     disp.push_str("| DNS_TYPE_AXFR");
    //     x = x & !0x00fc;
    // }
    // if x & 0x00fd == 0x00fd {
    //     disp.push_str("| DNS_TYPE_MAILB");
    //     x = x & !0x00fd;
    // }
    // if x & 0x00fe == 0x00fe {
    //     disp.push_str("| DNS_TYPE_MAILA");
    //     x = x & !0x00fe;
    // }
    // if x & 0x00ff == 0x00ff {
    //     disp.push_str("| DNS_TYPE_ALL");
    //     x = x & !0x00ff;
    // }
    // if x & 0x00ff == 0x00ff {
    //     disp.push_str("| DNS_TYPE_ANY");
    //     x = x & !0x00ff;
    // }
    // if x & 0xff01 == 0xff01 {
    //     disp.push_str("| DNS_TYPE_WINS");
    //     x = x & !0xff01;
    // }
    // if x & 0xff02 == 0xff02 {
    //     disp.push_str("| DNS_TYPE_WINSR");
    //     x = x & !0xff02;
    // }
    // if x & 0x0001 == 0x0001 {
    //     disp.push_str("| DNS_CLASS_INTERNET");
    //     x = x & !0x0001;
    // }
    // if x & 0x0002 == 0x0002 {
    //     disp.push_str("| DNS_CLASS_CSNET");
    //     x = x & !0x0002;
    // }
    // if x & 0x0003 == 0x0003 {
    //     disp.push_str("| DNS_CLASS_CHAOS");
    //     x = x & !0x0003;
    // }
    // if x & 0x0004 == 0x0004 {
    //     disp.push_str("| DNS_CLASS_HESIOD");
    //     x = x & !0x0004;
    // }
    // if x & 0x00fe == 0x00fe {
    //     disp.push_str("| DNS_CLASS_NONE");
    //     x = x & !0x00fe;
    // }
    // if x & 0x00ff == 0x00ff {
    //     disp.push_str("| DNS_CLASS_ALL");
    //     x = x & !0x00ff;
    // }
    // if x & 0x00ff == 0x00ff {
    //     disp.push_str("| DNS_CLASS_ANY");
    //     x = x & !0x00ff;
    // }
    // if x & 0x0000 == 0x0000 {
    //     disp.push_str("| DNS_OPCODE_QUERY");
    //     x = x & !0x0000;
    // }
    // if x & 0x0001 == 0x0001 {
    //     disp.push_str("| DNS_OPCODE_IQUERY");
    //     x = x & !0x0001;
    // }
    // if x & 0x0002 == 0x0002 {
    //     disp.push_str("| DNS_OPCODE_SERVER_STATUS");
    //     x = x & !0x0002;
    // }
    // if x & 0x0003 == 0x0003 {
    //     disp.push_str("| DNS_OPCODE_UNKNOWN");
    //     x = x & !0x0003;
    // }
    // if x & 0x0004 == 0x0004 {
    //     disp.push_str("| DNS_OPCODE_NOTIFY");
    //     x = x & !0x0004;
    // }
    // if x & 0x0005 == 0x0005 {
    //     disp.push_str("| DNS_OPCODE_UPDATE");
    //     x = x & !0x0005;
    // }
    // if x & 0x00000000 == 0x00000000 {
    //     disp.push_str("| DNSREC_QUESTION");
    //     x = x & !0x00000000;
    // }
    // if x & 0x00000001 == 0x00000001 {
    //     disp.push_str("| DNSREC_ANSWER");
    //     x = x & !0x00000001;
    // }
    // if x & 0x00000002 == 0x00000002 {
    //     disp.push_str("| DNSREC_AUTHORITY");
    //     x = x & !0x00000002;
    // }
    // if x & 0x00000003 == 0x00000003 {
    //     disp.push_str("| DNSREC_ADDITIONAL");
    //     x = x & !0x00000003;
    // }
    // if x & 0x00000000 == 0x00000000 {
    //     disp.push_str("| DNSREC_ZONE");
    //     x = x & !0x00000000;
    // }
    // if x & 0x00000001 == 0x00000001 {
    //     disp.push_str("| DNSREC_PREREQ");
    //     x = x & !0x00000001;
    // }
    // if x & 0x00000002 == 0x00000002 {
    //     disp.push_str("| DNSREC_UPDATE");
    //     x = x & !0x00000002;
    // }
    // if x & 0x00000004 == 0x00000004 {
    //     disp.push_str("| DNSREC_DELETE");
    //     x = x & !0x00000004;
    // }
    // if x & 0x00000004 == 0x00000004 {
    //     disp.push_str("| DNSREC_NOEXIST");
    //     x = x & !0x00000004;
    // }


    // if x & 0x00000000 == 0x00000000 {
    //     disp.push_str("| DNS_QUERY_STANDARD");
    //     x = x & !0x00000000;
    // }


    if x & 0x00000001 == 0x00000001 {
        disp.push_str("| DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE");
        x = x & !0x00000001;
    }
    if x & 0x00000002 == 0x00000002 {
        disp.push_str("| DNS_QUERY_USE_TCP_ONLY");
        x = x & !0x00000002;
    }
    if x & 0x00000004 == 0x00000004 {
        disp.push_str("| DNS_QUERY_NO_RECURSION");
        x = x & !0x00000004;
    }
    if x & 0x00000008 == 0x00000008 {
        disp.push_str("| DNS_QUERY_BYPASS_CACHE");
        x = x & !0x00000008;
    }
    if x & 0x00000010 == 0x00000010 {
        disp.push_str("| DNS_QUERY_NO_WIRE_QUERY");
        x = x & !0x00000010;
    }
    if x & 0x00000020 == 0x00000020 {
        disp.push_str("| DNS_QUERY_NO_LOCAL_NAME");
        x = x & !0x00000020;
    }
    if x & 0x00000040 == 0x00000040 {
        disp.push_str("| DNS_QUERY_NO_HOSTS_FILE");
        x = x & !0x00000040;
    }
    if x & 0x00000080 == 0x00000080 {
        disp.push_str("| DNS_QUERY_NO_NETBT");
        x = x & !0x00000080;
    }
    if x & 0x00000100 == 0x00000100 {
        disp.push_str("| DNS_QUERY_WIRE_ONLY");
        x = x & !0x00000100;
    }
    if x & 0x00000200 == 0x00000200 {
        disp.push_str("| DNS_QUERY_RETURN_MESSAGE");
        x = x & !0x00000200;
    }
    if x & 0x00000400 == 0x00000400 {
        disp.push_str("| DNS_QUERY_MULTICAST_ONLY");
        x = x & !0x00000400;
    }
    if x & 0x00000800 == 0x00000800 {
        disp.push_str("| DNS_QUERY_NO_MULTICAST");
        x = x & !0x00000800;
    }
    if x & 0x00001000 == 0x00001000 {
        disp.push_str("| DNS_QUERY_TREAT_AS_FQDN");
        x = x & !0x00001000;
    }
    if x & 0x00002000 == 0x00002000 {
        disp.push_str("| DNS_QUERY_ADDRCONFIG");
        x = x & !0x00002000;
    }
    if x & 0x00004000 == 0x00004000 {
        disp.push_str("| DNS_QUERY_DUAL_ADDR");
        x = x & !0x00004000;
    }
    if x & 0x00020000 == 0x00020000 {
        disp.push_str("| DNS_QUERY_MULTICAST_WAIT");
        x = x & !0x00020000;
    }
    if x & 0x00040000 == 0x00040000 {
        disp.push_str("| DNS_QUERY_MULTICAST_VERIFY");
        x = x & !0x00040000;
    }
    if x & 0x00100000 == 0x00100000 {
        disp.push_str("| DNS_QUERY_DONT_RESET_TTL_VALUES");
        x = x & !0x00100000;
    }
    if x & 0x00200000 == 0x00200000 {
        disp.push_str("| DNS_QUERY_DISABLE_IDN_ENCODING");
        x = x & !0x00200000;
    }
    if x & 0x00800000 == 0x00800000 {
        disp.push_str("| DNS_QUERY_APPEND_MULTILABEL");
        x = x & !0x00800000;
    }
    if x & 0xf0000000 == 0xf0000000 {
        disp.push_str("| DNS_QUERY_RESERVED");
        x = x & !0xf0000000;
    }
    // if x & 0x00000000 == 0x00000000 {
    //     disp.push_str("| DNS_UPDATE_SECURITY_USE_DEFAULT");
    //     x = x & !0x00000000;
    // }
    if x & 0x00000010 == 0x00000010 {
        disp.push_str("| DNS_UPDATE_SECURITY_OFF");
        x = x & !0x00000010;
    }
    if x & 0x00000020 == 0x00000020 {
        disp.push_str("| DNS_UPDATE_SECURITY_ON");
        x = x & !0x00000020;
    }
    if x & 0x00000100 == 0x00000100 {
        disp.push_str("| DNS_UPDATE_SECURITY_ONLY");
        x = x & !0x00000100;
    }
    if x & 0x00000200 == 0x00000200 {
        disp.push_str("| DNS_UPDATE_CACHE_SECURITY_CONTEXT");
        x = x & !0x00000200;
    }
    if x & 0x00000400 == 0x00000400 {
        disp.push_str("| DNS_UPDATE_TEST_USE_LOCAL_SYS_ACCT");
        x = x & !0x00000400;
    }
    if x & 0x00000800 == 0x00000800 {
        disp.push_str("| DNS_UPDATE_FORCE_SECURITY_NEGO");
        x = x & !0x00000800;
    }
    if x & 0x00001000 == 0x00001000 {
        disp.push_str("| DNS_UPDATE_TRY_ALL_MASTER_SERVERS");
        x = x & !0x00001000;
    }
    if x & 0x00002000 == 0x00002000 {
        disp.push_str("| DNS_UPDATE_SKIP_NO_UPDATE_ADAPTERS");
        x = x & !0x00002000;
    }
    if x & 0x00004000 == 0x00004000 {
        disp.push_str("| DNS_UPDATE_REMOTE_SERVER");
        x = x & !0x00004000;
    }
    if x & 0xffff0000 == 0xffff0000 {
        disp.push_str("| DNS_UPDATE_RESERVED");
        x = x & !0xffff0000;
    }


    if x & 0x800000000000 == 0x800000000000 {
        disp.push_str("| SYNC");
        x = x & !0x800000000000;
    }
    if x & 0x2000000000000 == 0x2000000000000 {
        disp.push_str("| CUSTOM_SERVER");
        x = x & !0x2000000000000;
    }



    if x != 0 {
        disp.push_str(&format!("| ... {:x}", x));
    }
    disp
}

fn first(s: &str, n: usize) -> &str {
    match s.get(..n) {
        Some(x) => x,
        None => s
    }
}
