//! Live NetworkManager integration tests.
//!
//! These tests talk to the **real** system bus, so they *skip* — rather than
//! fail — when NetworkManager is not reachable (`cargo test` must keep working
//! inside containers and on CI runners without a network stack).
//!
//! They exist because the D-Bus surface is easy to get subtly wrong: a method
//! name that does not exist, or a property read that is silently swallowed,
//! makes the program report "no Wi-Fi" on a machine that is happily online.
//! The assertions below always compare our derived state against
//! NetworkManager's own answer (`PrimaryConnectionType`), which is what makes
//! them able to catch that class of bug.

use proxywifi_core::networkmanager::NmClient;

/// `NM_DEVICE_TYPE_WIFI` from the `NMDeviceType` enum.
const NM_TYPE_WIRELESS: &str = "802-11-wireless";

/// Connect to NetworkManager, or `None` when it is unavailable.
async fn nm() -> Option<NmClient> {
    match NmClient::try_new().await {
        Some(nm) => Some(nm),
        None => {
            eprintln!("skipping: NetworkManager not reachable on the system bus");
            None
        }
    }
}

#[tokio::test]
async fn wifi_devices_have_an_interface_name() {
    let Some(nm) = nm().await else { return };

    let devices = nm
        .wifi_devices()
        .await
        .expect("wifi_devices() must not fail on a live system bus");

    for (path, iface) in &devices {
        assert!(
            path.as_str()
                .starts_with("/org/freedesktop/NetworkManager/Devices/"),
            "unexpected device object path {path}"
        );
        assert!(
            !iface.is_empty(),
            "device {path} was reported without an interface name"
        );
    }
}

#[tokio::test]
async fn saved_wifi_connections_are_well_formed() {
    let Some(nm) = nm().await else { return };

    let saved = nm
        .saved_wifi_connections()
        .await
        .expect("saved_wifi_connections() must not fail on a live system bus");

    for c in &saved {
        assert!(!c.uuid.is_empty(), "saved connection without a UUID: {c:?}");
        assert!(!c.name.is_empty(), "saved connection without a name: {c:?}");
        assert!(
            c.state == "activated" || c.state == "disconnected",
            "unexpected state {:?} for {}",
            c.state,
            c.uuid
        );
        if c.state == "activated" {
            assert!(
                c.active_connection_path.is_some(),
                "activated connection {} must carry its active-connection path",
                c.uuid
            );
        }
    }
}

/// The strong one: when NetworkManager says Wi-Fi owns the default route,
/// `active_wifi()` must agree — UUID, SSID, interface and addresses included.
#[tokio::test]
async fn active_wifi_agrees_with_networkmanager() {
    let Some(nm) = nm().await else { return };

    let primary_type = nm
        .primary_connection_type()
        .await
        .expect("primary_connection_type() must not fail on a live system bus");

    if primary_type != NM_TYPE_WIRELESS {
        eprintln!("skipping: Wi-Fi is not the primary connection (primary = {primary_type:?})");
        return;
    }

    let active = nm
        .active_wifi()
        .await
        .expect("active_wifi() must not fail on a live system bus")
        .expect("NetworkManager reports a Wi-Fi primary connection, so active_wifi() must find it");

    assert!(!active.uuid.is_empty(), "active Wi-Fi without a UUID");
    assert!(
        !active.interface.is_empty(),
        "active Wi-Fi without an interface name"
    );
    assert!(
        !active.ssid.is_empty(),
        "active Wi-Fi without an SSID (active AP lookup failed)"
    );
    assert!(
        active.has_default_route,
        "the primary connection must be the default-route connection"
    );
    assert!(
        active.ipv4.is_some() || active.ipv6.is_some(),
        "active Wi-Fi without any address"
    );

    // The same connection must be visible through the (independent) saved
    // connections path and be flagged active there.
    let saved = nm
        .saved_wifi_connections()
        .await
        .expect("saved_wifi_connections() must not fail on a live system bus");
    let matching = saved
        .iter()
        .find(|c| c.uuid == active.uuid)
        .unwrap_or_else(|| {
            panic!(
                "active Wi-Fi {} is missing from the saved connection list",
                active.uuid
            )
        });
    assert_eq!(
        matching.state, "activated",
        "connection {} is active but not flagged as activated",
        active.uuid
    );
}

#[tokio::test]
async fn available_networks_include_the_connected_ssid() {
    let Some(nm) = nm().await else { return };

    let Some(active) = nm.active_wifi().await.expect("active_wifi() must not fail") else {
        eprintln!("skipping: not associated with a Wi-Fi network");
        return;
    };

    let networks = nm
        .available_wifi_networks()
        .await
        .expect("available_wifi_networks() must not fail on a live system bus");

    assert!(
        !networks.is_empty(),
        "a device associated with {:?} must report at least that access point",
        active.ssid
    );

    // Strongest first.
    for pair in networks.windows(2) {
        assert!(
            pair[0].1 >= pair[1].1,
            "access points are not sorted by signal strength: {pair:?}"
        );
    }

    if !active.ssid.is_empty() {
        // Hidden SSIDs are skipped by the query, so this is only asserted for
        // a visible, associated network.
        assert!(
            networks.iter().any(|(ssid, _)| *ssid == active.ssid),
            "the associated SSID {:?} is missing from the access point list",
            active.ssid
        );
    }
}
