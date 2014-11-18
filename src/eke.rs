//! Encrypted Key Exchange
//!
//! Implement a EKE variant close from
//! [AuthA](http://grouper.ieee.org/groups/1363/passwdPK/contributions/autha.pdf)
//! and [SPAKE](http://www.di.ens.fr/~abdalla/papers/AbPo05a-letter.pdf)
//! where the result of `Hash(password)` is mapped to a group element on
//! the elliptic curve `Curve41417` through the
//! [Elligator 2](http://elligator.cr.yp.to/) mapping function.
use std::io::Reader;

use common::sbuf::{Allocator, SBuf};
use common::utils;
use curve41417;
use curve41417::bytes::{Bytes, B512, Scalar, EdPoint};
use curve41417::ed::GroupElem;

use hash::Hash;
use self::Role::*;
use self::State::*;
use self::Status::*;
use sha3::{Sha3, Sha3Mode};


const CONFIRMK_SIZE: uint = 64;


macro_rules! try_ongoing(
    ($e:expr) => (match $e { Ongoing => (), _ => return Err(()) })
)


/// Peer's role
pub enum Role {
    Client,
    Server
}

/// Protocol's status
enum Status {
    Ongoing,
    Success,
    Failed
}

/// Protocol's state
enum State {
    ClientCommitSnd,
    ClientCommitConfirmRcv,
    ClientConfirmSnd,
    ServerCommitRcv,
    ServerCommitConfirmSnd,
    ServerConfirmRcv,
    Done
}

/// Encrypted key exchange
///
/// After having instanciated a new instance with a defined role, iteratively
/// call `get_msg()` to get the next message to send to the other peer and
/// then call `process_msg()` to process the remote message received from this
/// peer. After each call to these methods call `is_done()` to know if the
/// protocol has reached its final state. Control if the protocol succeeded
/// by calling `is_success()`, in this case the final session key shared by
/// both peers becomes available through the method `session_key()`.
///
/// The expected protocol messages flow is the following:
///
/// ```ignore
/// C -> S: X*                  [commit]
/// S -> C: Y* || Confirm       [commit, confirm]
/// C -> S: Confirm             [confirm]
/// ```
pub struct Eke<A> {
    role: Role,
    status: Status,
    state: State,
    secret: GroupElem<A>,
    sender_privkey: Scalar<A>,
    sender_star: SBuf<A, u8>,
    sess_key: Sha3<A>
}


impl<A: Allocator> Eke<A> {
    /// Create a new `Eke` instance with defined caller's `role`.
    /// `client_info` and `server_info` are additional infos to be
    /// hashed in the confirmation messages and in the final session
    /// key. `secret` is the shared secret between both peers.
    pub fn new(role: Role, client_info: Option<&[u8]>,
               server_info: Option<&[u8]>,
               secret: &[u8]) -> Result<Eke<A>, ()> {
        // Hash secret.
        let mut state: Sha3<A> = Sha3::new(Sha3Mode::Sha3_512);
        try_ok_unit!(secret.hash(&mut state));
        let mut key: B512<A> = Bytes::new_zero();
        assert!(state.digest_length() == key.len());
        try_ok_unit!(state.read(key.as_mut_bytes()));

        // Hash infos into session key's state.
        let mut sk: Sha3<A> = Sha3::new(Sha3Mode::Shake256);
        if client_info.is_some() {
            try_ok_unit!(client_info.as_ref().unwrap().hash(&mut sk));
        }
        if server_info.is_some() {
            try_ok_unit!(server_info.as_ref().unwrap().hash(&mut sk));
        }

        // Map password key to group element ψ(Hash(secret)).
        let mut secret_pt = try_some_err!(
            GroupElem::<A>::elligator_from_bytes(&key));
        secret_pt = secret_pt.scalar_mult_cofactor();

        // Generate commit keypair.
        let (sender_pubkey, sender_privkey) = GroupElem::keypair();

        // Compute [X|Y]* = sender_pubkey + ψ(Hash(password)).
        let sender_star = (sender_pubkey + secret_pt).pack().unwrap().unwrap();

        // Initial state depending on associated role.
        let state = match role {
            Client => ClientCommitSnd,
            Server => ServerCommitRcv
        };

        Ok(Eke {
            role: role,
            status: Ongoing,
            state: state,
            secret: secret_pt,
            sender_privkey: sender_privkey,
            sender_star: sender_star,
            sess_key: sk
        })
    }

    /// Return `true` if the final state of the protocol is reached, in which
    /// case `get_msg()` and `process_msg()` must not be called afterward.
    pub fn is_done(&self) -> bool {
        match self.state {
            Done => true,
            _ => false
        }
    }

    /// Return `true` if the final state is reached on a success.
    pub fn is_success(&self) -> bool {
        match (self.is_done(), self.status) {
            (true, Success) => true,
            _ => false
        }
    }

    /// Return the protocol message corresponding to the current state, or
    /// an irrecoverable error on error. The resulting message is expected
    /// to be the input message argument of `process_msg()` usually called
    /// from another peer.
    pub fn get_msg(&mut self) -> Result<SBuf<A, u8>, ()> {
        try_ongoing!(self.status);

        let r = match self.state {
            ClientCommitSnd => self.commit(),
            ClientConfirmSnd => self.confirm(),
            ServerCommitConfirmSnd => self.commit_confirm(),
            _ => return Err(())
        };

        if r.is_err() {
            self.set_failed();
            return r;
        }

        match self.state {
            ClientCommitSnd => self.state = ClientCommitConfirmRcv,
            ClientConfirmSnd => self.set_succeeded(),
            ServerCommitConfirmSnd => self.state = ServerConfirmRcv,
            _ => ()
        }
        r
    }

    /// Process a message `msg` obtained from `get_msg()` usually called from
    /// another peer; otherwise return an irrecoverable error on error.
    pub fn process_msg(&mut self, msg: &[u8]) -> Result<(), ()> {
        try_ongoing!(self.status);

        let r = match self.state {
            ClientCommitConfirmRcv => self.process_commit_confirm(msg),
            ServerCommitRcv => self.process_commit(msg),
            ServerConfirmRcv => self.process_confirm(msg),
            _ => return Err(())
        };

        if r.is_err() {
            self.set_failed();
            return Err(());
        }

        match self.state {
            ClientCommitConfirmRcv => self.state = ClientConfirmSnd,
            ServerCommitRcv => self.state = ServerCommitConfirmSnd,
            ServerConfirmRcv => self.set_succeeded(),
            _ => ()
        }

        Ok(())
    }

    fn set_failed(&mut self) {
        self.status = Failed;
        self.state = Done;
    }

    fn set_succeeded(&mut self) {
        self.status = Success;
        self.state = Done;
    }

    fn is_client(&self) -> bool {
        match self.role {
            Client => true,
            Server => false
        }
    }

    fn commit(&mut self) -> Result<SBuf<A, u8>, ()> {
        Ok(self.sender_star.clone())
    }

    fn process_commit(&mut self, peer_star: &[u8]) -> Result<(), ()> {
        let psb = try_some_err!(Bytes::from_bytes(peer_star));
        let ps = try_some_err!(GroupElem::unpack(&EdPoint(psb)));

        // Hash star fields into session key's state.
        if self.is_client() {
            try_ok_unit!(self.sender_star[].hash(&mut self.sess_key));
            try_ok_unit!(peer_star.hash(&mut self.sess_key));
        } else {
            try_ok_unit!(peer_star.hash(&mut self.sess_key));
            try_ok_unit!(self.sender_star[].hash(&mut self.sess_key));
        }

        // Hash initial secret into session key's state.
        let secret = self.secret.pack().unwrap();
        try_ok_unit!(secret.as_bytes().hash(&mut self.sess_key));

        // Hash shared DH key into session key's state.
        let sk = (ps - self.secret).scalar_mult(
            &self.sender_privkey).pack().unwrap();
        try_ok_unit!(sk.as_bytes().hash(&mut self.sess_key));

        Ok(())
    }

    fn confirm(&mut self) -> Result<SBuf<A, u8>, ()> {
        let mut sk = self.sess_key.clone();
        let mut cm: SBuf<A, u8> = SBuf::new_zero(CONFIRMK_SIZE);
        if self.is_client() {
            try_ok_unit!(sk.read(cm[mut]));
        } else {
            try_ok_unit!(sk.skip(CONFIRMK_SIZE));
            try_ok_unit!(sk.read(cm[mut]));
        }
        Ok(cm)
    }

    fn process_confirm(&mut self, confirm: &[u8]) -> Result<(), ()> {
        let mut sk = self.sess_key.clone();
        let mut cm: SBuf<A, u8> = SBuf::new_zero(CONFIRMK_SIZE);
        if self.is_client() {
            try_ok_unit!(sk.skip(CONFIRMK_SIZE));
            try_ok_unit!(sk.read(cm[mut]));
        } else {
            try_ok_unit!(sk.read(cm[mut]));
        }

        // Check confirmation.
        if !utils::bytes_eq(confirm, cm[]) {
            return Err(());
        }
        Ok(())
    }

    fn commit_confirm(&mut self) -> Result<SBuf<A, u8>, ()> {
        let commit = try!(self.commit());
        let confirm = try!(self.confirm());
        Ok(SBuf::from_sbufs(&[&commit, &confirm]))
    }

    fn process_commit_confirm(&mut self, msg: &[u8]) -> Result<(), ()> {
        if msg.len() != curve41417::POINT_SIZE + CONFIRMK_SIZE {
            return Err(());
        }

        try!(self.process_commit(msg[..curve41417::POINT_SIZE]));
        try!(self.process_confirm(msg[curve41417::POINT_SIZE..]));
        Ok(())
    }

    /// Return the final session key shared by both peers or an error
    /// if the protocol is not in the final state or has failed in a
    /// previous step.
    pub fn session_key(&mut self, size: uint) -> Result<SBuf<A, u8>, ()> {
        if !self.is_success() {
            return Err(())
        }

        let mut s = self.sess_key.clone();
        // Discard confirmation buffers.
        try_ok_unit!(s.skip(2 * CONFIRMK_SIZE));
        let mut sk: SBuf<A, u8> = SBuf::new_zero(size);
        try_ok_unit!(s.read(sk[mut]));
        Ok(sk)
    }
}

impl<A: Allocator> Clone for Eke<A> {
    fn clone(&self) -> Eke<A> {
        Eke {
            role: self.role,
            status: self.status,
            state: self.state,
            secret: self.secret.clone(),
            sender_privkey: self.sender_privkey.clone(),
            sender_star: self.sender_star.clone(),
            sess_key: self.sess_key.clone()
        }
    }
}


#[cfg(test)]
mod tests {
    use common::sbuf::{DefaultAllocator, SBuf};

    use eke::{mod, Role, State, Status};


    #[test]
    fn test_exchange() {
        let session_key_size = 32u;

        // Shared password
        let password: SBuf<DefaultAllocator, u8> = SBuf::new_rand(32);

        // Client
        let mut pakec: eke::Eke<DefaultAllocator> =
            eke::Eke::new(Role::Client, Some(b"C"), Some(b"S"),
                          password[]).ok().unwrap();

        // Server
        let mut pakes: eke::Eke<DefaultAllocator> =
            eke::Eke::new(Role::Server, Some(b"C"), Some(b"S"),
                          password[]).ok().unwrap();

        // Stars messages exchange
        assert!(pakec.state as int == State::ClientCommitSnd as int);
        assert!(pakes.state as int == State::ServerCommitRcv as int);

        // C -> S: X*
        let mc1 = pakec.get_msg().ok().unwrap();
        assert!(pakec.state as int == State::ClientCommitConfirmRcv as int);

        assert!(pakes.process_msg(mc1[]).is_ok());
        assert!(pakes.state as int == State::ServerCommitConfirmSnd as int);

        // S -> C: Y* || Confirm
        let ms1 = pakes.get_msg().ok().unwrap();
        assert!(pakes.state as int == State::ServerConfirmRcv as int);

        assert!(pakec.process_msg(ms1[]).is_ok());
        assert!(pakec.state as int == State::ClientConfirmSnd as int);

        // C -> S: Confirm
        let mc2 = pakec.get_msg().ok().unwrap();
        assert!(pakec.state as int == State::Done as int);
        assert!(pakec.is_done());
        assert!(pakec.status as int == Status::Success as int);

        assert!(pakes.process_msg(mc2[]).is_ok());
        assert!(pakes.state as int == State::Done as int);
        assert!(pakes.is_done());
        assert!(pakes.status as int == Status::Success as int);

        // Check session key
        let skc = pakec.session_key(session_key_size).ok().unwrap();
        let sks = pakes.session_key(session_key_size).ok().unwrap();
        assert!(skc.len() == session_key_size);
        assert!(skc == sks);

        // Sanity check
        assert!(pakec.get_msg().is_err());
        assert!(pakes.get_msg().is_err());
        assert!(pakec.process_msg(ms1[]).is_err());
        assert!(pakes.process_msg(mc2[]).is_err());
    }
}
