//! Group duplicate logon sessions for display, preserving first-seen order.

use std::collections::{HashMap, hash_map::Entry};

use vmkatz::lsass::types::{Credential, KerberosKey};

#[derive(PartialEq, Eq, Hash)]
struct SessionKey {
    username: String,
    domain: String,
    nt_hash: Option<[u8; 16]>,
}

/// Merge sessions with the same case-insensitive identity and optional NT hash.
pub(super) fn dedup_credentials(credentials: &[Credential]) -> Vec<Credential> {
    let mut group_indices = HashMap::new();
    let mut merged = Vec::new();

    for credential in credentials {
        let key = SessionKey {
            username: credential.username.to_ascii_lowercase(),
            domain: credential.domain.to_ascii_lowercase(),
            nt_hash: credential.msv.as_ref().map(|msv| msv.nt_hash),
        };

        // The Vec preserves first-seen order; the map only locates existing groups.
        match group_indices.entry(key) {
            Entry::Occupied(entry) => merge_session(&mut merged[*entry.get()], credential),
            Entry::Vacant(entry) => {
                entry.insert(merged.len());
                merged.push(clone_for_display(credential));
            }
        }
    }
    merged
}

/// Copy a representative session, omitting empty password-only records.
fn clone_for_display(base: &Credential) -> Credential {
    Credential {
        luid: base.luid,
        username: base.username.clone(),
        domain: base.domain.clone(),
        logon_type: base.logon_type,
        session_id: base.session_id,
        logon_time: base.logon_time,
        logon_server: base.logon_server.clone(),
        sid: base.sid.clone(),
        msv: base.msv.clone(),
        wdigest: base
            .wdigest
            .as_ref()
            .filter(|w| !w.password.is_empty())
            .cloned(),
        kerberos: base.kerberos.clone(),
        tspkg: base
            .tspkg
            .as_ref()
            .filter(|t| !t.password.is_empty())
            .cloned(),
        dpapi: base.dpapi.clone(),
        credman: base.credman.clone(),
        ssp: base
            .ssp
            .as_ref()
            .filter(|s| !s.password.is_empty())
            .cloned(),
        livessp: base
            .livessp
            .as_ref()
            .filter(|l| !l.password.is_empty())
            .cloned(),
        cloudap: base.cloudap.clone(),
    }
}

/// Preserve the first values, filling gaps and appending unique provider records.
fn merge_session(merged: &mut Credential, donor: &Credential) {
    if donor.logon_time != 0 && (merged.logon_time == 0 || donor.logon_time < merged.logon_time) {
        merged.logon_time = donor.logon_time;
    }
    if merged.sid.is_empty() && !donor.sid.is_empty() {
        merged.sid.clone_from(&donor.sid);
    }
    if merged.logon_server.is_empty() && !donor.logon_server.is_empty() {
        merged.logon_server.clone_from(&donor.logon_server);
    }

    if merged.wdigest.is_none() {
        if let Some(wd) = donor.wdigest.as_ref().filter(|w| !w.password.is_empty()) {
            merged.wdigest = Some(wd.clone());
        }
    }

    // Kerberos: merge unique keys, tickets, password
    if let Some(donor_krb) = &donor.kerberos {
        if let Some(merged_krb) = &mut merged.kerberos {
            if merged_krb.password.is_empty() && !donor_krb.password.is_empty() {
                merged_krb.password.clone_from(&donor_krb.password);
            }
            for key in &donor_krb.keys {
                if merged_krb.keys.iter().all(|k| k.key != key.key) {
                    merged_krb.keys.push(KerberosKey {
                        etype: key.etype,
                        key: key.key.clone(),
                    });
                }
            }
            for ticket in &donor_krb.tickets {
                if merged_krb
                    .tickets
                    .iter()
                    .all(|t| t.service_name != ticket.service_name)
                {
                    merged_krb.tickets.push(ticket.clone());
                }
            }
        } else {
            merged.kerberos = Some(donor_krb.clone());
        }
    }

    // DPAPI: collect unique by GUID
    for dk in &donor.dpapi {
        if !merged.dpapi.iter().any(|d| d.guid == dk.guid) {
            merged.dpapi.push(dk.clone());
        }
    }

    // CredMan: collect unique by target
    for cm in &donor.credman {
        if !merged.credman.iter().any(|c| c.target == cm.target) {
            merged.credman.push(cm.clone());
        }
    }

    // TsPkg, SSP, LiveSSP, CloudAP: keep first non-empty
    if merged.tspkg.is_none() {
        merged.tspkg = donor
            .tspkg
            .as_ref()
            .filter(|t| !t.password.is_empty())
            .cloned();
    }
    if merged.ssp.is_none() {
        merged.ssp = donor
            .ssp
            .as_ref()
            .filter(|s| !s.password.is_empty())
            .cloned();
    }
    if merged.livessp.is_none() {
        merged.livessp = donor
            .livessp
            .as_ref()
            .filter(|l| !l.password.is_empty())
            .cloned();
    }
    if merged.cloudap.is_none() {
        merged.cloudap.clone_from(&donor.cloudap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmkatz::lsass::types::{
        CredmanCredential, DpapiCredential, KerberosCredential, KerberosTicket, KerberosTicketType,
        LiveSspCredential, MsvCredential, SspCredential, TspkgCredential, WdigestCredential,
    };

    fn session(user: &str, domain: &str, luid: u64, hash: Option<u8>) -> Credential {
        Credential {
            luid,
            username: user.into(),
            domain: domain.into(),
            msv: hash.map(|byte| MsvCredential {
                username: user.into(),
                domain: domain.into(),
                nt_hash: [byte; 16],
                lm_hash: [0; 16],
                sha1_hash: [0; 20],
            }),
            ..Credential::default()
        }
    }

    fn set_passwords(session: &mut Credential, password: &str) {
        session.wdigest = Some(WdigestCredential {
            username: "test".into(),
            domain: "LAB".into(),
            password: password.into(),
        });
        session.tspkg = Some(TspkgCredential {
            username: "test".into(),
            domain: "LAB".into(),
            password: password.into(),
        });
        session.ssp = Some(SspCredential {
            username: "test".into(),
            domain: "LAB".into(),
            password: password.into(),
        });
        session.livessp = Some(LiveSspCredential {
            username: "test".into(),
            domain: "LAB".into(),
            password: password.into(),
        });
    }

    fn ticket(service: &str, time: u64) -> KerberosTicket {
        KerberosTicket {
            ticket_type: KerberosTicketType::Tgs,
            service_name: vec![service.into()],
            service_name_type: 2,
            client_name: vec!["test".into()],
            client_name_type: 1,
            domain_name: "LAB".into(),
            target_domain_name: "LAB".into(),
            ticket_flags: 0,
            key_type: 17,
            session_key: vec![1; 16],
            start_time: time,
            end_time: time + 1,
            renew_until: time + 2,
            ticket_enc_type: 17,
            ticket_kvno: 1,
            ticket_blob: vec![],
            kirbi: vec![],
        }
    }

    #[test]
    fn grouping_preserves_order_case_and_distinct_hashes() {
        let input = vec![
            session("Alice", "LAB", 1, Some(1)),
            session("Bob", "LAB", 2, Some(1)),
            session("aLiCe", "lab", 3, Some(1)),
            session("Alice", "LAB", 4, Some(2)),
            session("Alice", "OTHER", 5, Some(1)),
            session("Alice", "LAB", 6, None),
            session("alice", "lab", 7, None),
        ];
        let output = dedup_credentials(&input);
        assert_eq!(
            output.iter().map(|c| c.luid).collect::<Vec<_>>(),
            [1, 2, 4, 5, 6]
        );
        assert_eq!(output[0].username, "Alice");
        assert_eq!(output[0].domain, "LAB");
    }

    #[test]
    fn missing_msv_does_not_alias_a_present_hash() {
        for hash in [0, 0xFF] {
            for (first, second) in [(None, Some(hash)), (Some(hash), None)] {
                let mut input = vec![
                    session("Alice", "LAB", 1, first),
                    session("alice", "lab", 2, second),
                    session("ALICE", "LAB", 3, first),
                ];
                set_passwords(&mut input[1], "other group");
                set_passwords(&mut input[2], "same group");

                let output = dedup_credentials(&input);
                assert_eq!(output.len(), 2);
                assert_eq!([output[0].luid, output[1].luid], [1, 2]);
                assert_eq!(
                    output[0].msv.as_ref().map(|m| m.nt_hash),
                    first.map(|h| [h; 16])
                );
                assert_eq!(
                    output[1].msv.as_ref().map(|m| m.nt_hash),
                    second.map(|h| [h; 16])
                );
                assert_eq!(
                    output[0].wdigest.as_ref().map(|w| w.password.as_str()),
                    Some("same group")
                );
                assert_eq!(
                    output[1].wdigest.as_ref().map(|w| w.password.as_str()),
                    Some("other group")
                );
            }
        }
    }

    #[test]
    fn group_lookup_preserves_order_and_matches_after_growth() {
        let mut input: Vec<_> = (0..256)
            .map(|id| session(&format!("user-{id}"), "LAB", id, Some(1)))
            .collect();
        for id in (0..256).rev() {
            let mut donor = session(&format!("USER-{id}"), "lab", id + 256, Some(1));
            donor.sid = format!("SID-{id}");
            input.push(donor);
        }

        let output = dedup_credentials(&input);
        assert_eq!(output.len(), 256);
        for (id, session) in (0..256).zip(output) {
            assert_eq!(session.luid, id);
            assert_eq!(session.username, format!("user-{id}"));
            assert_eq!(session.sid, format!("SID-{id}"));
        }
    }

    #[test]
    fn singleton_omits_empty_password_records_without_changing_input() {
        let mut input = session("Alice", "LAB", 1, None);
        set_passwords(&mut input, "");
        let output = dedup_credentials(std::slice::from_ref(&input));
        assert!(output[0].wdigest.is_none());
        assert!(output[0].tspkg.is_none());
        assert!(output[0].ssp.is_none());
        assert!(output[0].livessp.is_none());
        assert!(input.wdigest.is_some());
    }

    #[test]
    fn merge_fills_gaps_keeps_first_passwords_and_earliest_known_time() {
        let mut input = vec![
            session("Alice", "LAB", 1, None),
            session("alice", "lab", 2, None),
            session("ALICE", "LAB", 3, None),
        ];
        set_passwords(&mut input[0], "");
        set_passwords(&mut input[1], "first");
        input[1].logon_time = 30;
        input[1].sid = "first SID".into();
        input[1].logon_server = "first server".into();
        set_passwords(&mut input[2], "later");
        input[2].logon_time = 10;
        input[2].sid = "later SID".into();
        input[2].logon_server = "later server".into();
        let output = dedup_credentials(&input);
        let merged = &output[0];
        assert_eq!(merged.luid, 1);
        assert_eq!(merged.logon_time, 10);
        assert_eq!(merged.sid, "first SID");
        assert_eq!(merged.logon_server, "first server");
        assert_eq!(merged.wdigest.as_ref().unwrap().password, "first");
        assert_eq!(merged.tspkg.as_ref().unwrap().password, "first");
        assert_eq!(merged.ssp.as_ref().unwrap().password, "first");
        assert_eq!(merged.livessp.as_ref().unwrap().password, "first");
    }

    #[test]
    fn provider_records_keep_their_existing_uniqueness_rules() {
        let mut input = vec![
            session("Alice", "LAB", 1, None),
            session("alice", "lab", 2, None),
        ];
        for (index, session) in input.iter_mut().enumerate() {
            session.kerberos = Some(KerberosCredential {
                username: "Alice".into(),
                domain: "LAB".into(),
                password: if index == 0 { "" } else { "first" }.into(),
                keys: vec![KerberosKey {
                    etype: 17 + index as u32,
                    key: vec![1; 16],
                }],
                tickets: vec![ticket("same-service", index as u64)],
            });
            session.dpapi.push(DpapiCredential {
                guid: "same-guid".into(),
                key: vec![index as u8],
                sha1_masterkey: [0; 20],
            });
            session.credman.push(CredmanCredential {
                username: "Alice".into(),
                domain: "LAB".into(),
                password: index.to_string(),
                target: "same-target".into(),
            });
        }
        let extra = input[1].kerberos.as_mut().unwrap();
        extra.keys.push(KerberosKey {
            etype: 23,
            key: vec![2; 16],
        });
        extra.tickets.push(ticket("other-service", 2));
        input[1].dpapi.push(DpapiCredential {
            guid: "other-guid".into(),
            key: vec![2],
            sha1_masterkey: [0; 20],
        });
        input[1].credman.push(CredmanCredential {
            username: "Alice".into(),
            domain: "LAB".into(),
            password: "2".into(),
            target: "other-target".into(),
        });

        let output = dedup_credentials(&input);
        let merged = &output[0];
        let kerberos = merged.kerberos.as_ref().unwrap();
        assert_eq!(kerberos.password, "first");
        assert_eq!(kerberos.keys.len(), 2);
        assert_eq!(kerberos.keys[0].etype, 17);
        assert_eq!(kerberos.keys[1].key, vec![2; 16]);
        assert_eq!(kerberos.tickets.len(), 2);
        assert_eq!(kerberos.tickets[0].start_time, 0);
        assert_eq!(kerberos.tickets[1].service_name, ["other-service"]);
        assert_eq!(merged.dpapi.len(), 2);
        assert_eq!(merged.dpapi[0].key, [0]);
        assert_eq!(merged.dpapi[1].guid, "other-guid");
        assert_eq!(merged.credman.len(), 2);
        assert_eq!(merged.credman[0].password, "0");
        assert_eq!(merged.credman[1].target, "other-target");
    }
}
