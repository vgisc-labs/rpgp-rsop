use openpgp_card::ocard::Transaction;
use openpgp_card::state::Open;
use openpgp_card_rpgp::CardSlot;
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::{PublicKeyTrait, PublicParams};
use pgp::Message;
use rand::thread_rng;
use rpgpie::Error;

/// Helper fn to make a data signature on an OpenPGP card.
///
/// FIXME: Hardwired to use key slot "sign" for now.
pub(crate) fn sign_on_card(
    msg: &Message,
    pp: &PublicParams,
    hash_algorithm: HashAlgorithm,
    touch_prompt: &(dyn Fn() + Send + Sync),
) -> Result<Message, Error> {
    // FIXME: card_by_pp reads data from the card that is lost at the boundary of this call -> fix the API
    if let Ok(Some(mut card)) = card_by_pp(pp, openpgp_card::ocard::KeyType::Signing) {
        let mut tx = card.transaction().expect("FIXME");

        verify_pin_from_card_state(tx.card(), true)?;

        let cs =
            CardSlot::init_from_card(&mut tx, openpgp_card::ocard::KeyType::Signing, touch_prompt)?;

        Ok(msg
            .clone()
            .sign(&mut thread_rng(), &cs, String::default, hash_algorithm)?)
    } else {
        Err(Error::Message("Card not found".to_string()))
    }
}

/// Get a card based on matching available cards with public key parameters.
///
/// FIXME: replace with a filter function, so main can directly iterate over cards.
/// Caller shouldn't need to re-open a transaction (?)
pub fn card_by_pp(
    pp: &PublicParams,
    kt: openpgp_card::ocard::KeyType,
) -> Result<Option<openpgp_card::Card<Open>>, Error> {
    let Ok(backends) = card_backend_pcsc::PcscBackend::cards(None) else {
        return Ok(None);
    };

    for b in backends.filter_map(|c| c.ok()) {
        if let Ok(mut card) = openpgp_card::Card::<Open>::new(b) {
            // signals that this is the right card
            let mut found = false;

            {
                if let Ok(mut tx) = card.transaction() {
                    let cs = CardSlot::init_from_card(&mut tx, kt, &|| {})?;

                    if cs.public_key().public_params() == pp {
                        found = true;
                    }
                }
            }

            if found {
                return Ok(Some(card));
            }
        }
    }

    Ok(None)
}

/// Get the User PIN for the card via openpgp_card_state, and present it to the card.
///
/// If the card rejects the User PIN, it is dropped from openpgp_card_state.
pub fn verify_pin_from_card_state(tx: &mut Transaction, sign: bool) -> Result<(), Error> {
    let ard = tx.application_related_data().expect("FIXME");
    let ident = ard.application_id().expect("FIXME").ident();

    if let Ok(Some(pin)) = openpgp_card_state::get_pin(&ident) {
        let verify = match sign {
            true => Transaction::verify_pw1_sign,
            false => Transaction::verify_pw1_user,
        };

        if verify(tx, pin.as_bytes().to_vec().into()).is_err() {
            // We drop the PIN from the state backend, to avoid exhausting
            // the retry counter and locking up the User PIN.
            let res = openpgp_card_state::drop_pin(&ident);

            if res.is_ok() {
                eprintln!(
                    "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! Dropped it from storage.",
                    &ident);
            } else {
                eprintln!(
                    "ERROR: The stored User PIN for OpenPGP card '{}' seems wrong or blocked! In addition, dropping it from storage failed.",
                    &ident);
            }

            return Err(Error::Message("User PIN verification failed.".to_string()));
        }
    } else {
        return Err(Error::Message("No User PIN configured.".to_string()));
    }

    Ok(())
}
