//! Diagnostic: list the OpenPGP packets in a message and try a passphrase.
//! Usage: cargo run --example inspect -- <file.asc> [passphrase]

use std::io::Read;

use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let bytes = std::fs::read(&args[1])?;

    println!("== packets ==");
    let mut ppr = PacketParser::from_bytes(&bytes)?;
    while let PacketParserResult::Some(pp) = ppr {
        println!("  tag={:?}", pp.packet.tag());
        match pp.next() {
            Ok((_, next)) => ppr = next,
            Err(e) => {
                println!("  (next error: {e})");
                break;
            }
        }
    }

    // v6 fast-path: parse the SKESK ourselves and (optionally) verify.
    match bruteforcer::target::skesk_v6::SkeskV6::parse(&bytes) {
        Ok(s) => {
            println!(
                "== v6 SKESK parsed == salt={} count={} iv={}B esk={}B",
                hex(&s.salt),
                s.count,
                s.iv.len(),
                s.esk.len()
            );
            if let Some(pass) = args.get(2) {
                match s.verify(pass.as_bytes()) {
                    Some(sk) => println!("  fast-path VERIFIED, session_key={}", hex(&sk[..8.min(sk.len())])),
                    None => println!("  fast-path rejected passphrase"),
                }
            }
        }
        Err(e) => println!("== v6 fast-path N/A: {e} =="),
    }

    if let Some(pass) = args.get(2) {
        println!("== try passphrase {:?} ==", pass);
        use sequoia_openpgp::crypto::{Password, SessionKey};
        use sequoia_openpgp::packet::{PKESK, SKESK};
        use sequoia_openpgp::parse::stream::{
            DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
        };
        use sequoia_openpgp::policy::StandardPolicy;
        use sequoia_openpgp::types::SymmetricAlgorithm;
        use sequoia_openpgp::{Cert, KeyHandle};

        struct H {
            p: Password,
        }
        impl VerificationHelper for H {
            fn get_certs(&mut self, _: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
                Ok(vec![])
            }
            fn check(&mut self, _: MessageStructure) -> sequoia_openpgp::Result<()> {
                Ok(())
            }
        }
        impl DecryptionHelper for H {
            fn decrypt(
                &mut self,
                _: &[PKESK],
                skesks: &[SKESK],
                _: Option<SymmetricAlgorithm>,
                decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
            ) -> sequoia_openpgp::Result<Option<Cert>> {
                println!("  helper saw {} SKESK packet(s)", skesks.len());
                for s in skesks {
                    match s.decrypt(&self.p) {
                        Ok((algo, sk)) => {
                            println!("  skesk.decrypt ok, algo={algo:?}");
                            if decrypt(algo, &sk) {
                                return Ok(None);
                            }
                        }
                        Err(e) => println!("  skesk.decrypt err: {e}"),
                    }
                }
                Err(anyhow::anyhow!("no skesk decrypted"))
            }
        }

        let policy = Box::leak(Box::new(StandardPolicy::new()));
        let h = H {
            p: Password::from(pass.as_bytes()),
        };
        match DecryptorBuilder::from_bytes(&bytes)?.with_policy(policy, None, h) {
            Ok(mut d) => {
                let mut out = Vec::new();
                d.read_to_end(&mut out)?;
                println!("  DECRYPTED: {}", String::from_utf8_lossy(&out));
            }
            Err(e) => println!("  decrypt failed: {e:?}"),
        }
    }
    Ok(())
}
